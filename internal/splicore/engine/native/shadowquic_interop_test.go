//go:build with_quic && with_utls

package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowquic"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	quic "github.com/metacubex/jls-quic-go"
	tls "github.com/metacubex/jls-tls"
)

// The pinned peer is only a qualification tool. No production path executes it.
func sqReference(t *testing.T, config string, port int, network string) *exec.Cmd {
	t.Helper()
	bin := os.Getenv("SPLICORE_SHADOWQUIC_REFERENCE")
	root := os.Getenv("SPLICORE_SHADOWQUIC_EVIDENCE")
	if bin == "" || root == "" {
		t.Skip("explicit pinned ShadowQUIC reference campaign required")
	}
	b, e := os.ReadFile(bin)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(b)
	want := map[string]string{
		"linux/amd64":   "f35e6ab3d8dafb46d8f3efecb3805bf8a1a2c33fb27967aeaaa13e877bf86bc5",
		"windows/amd64": "5656ada0f81e96f30cf2c5311d988bc386123999496bcaa8b08f3cd04173736f",
	}[runtime.GOOS+"/"+runtime.GOARCH]
	if want == "" || hex.EncodeToString(sum[:]) != want {
		t.Fatal("reference digest")
	}
	path := filepath.Join(t.TempDir(), "reference.yaml")
	if e = os.WriteFile(path, []byte(config), 0o600); e != nil {
		t.Fatal(e)
	}
	log, e := os.Create(filepath.Join(root, testkit.EvidenceName(t.Name())+"-reference.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(bin, "-c", path)
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		log.Close()
		t.Fatal(e)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done; _ = log.Close() })
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		select {
		case <-done:
			data, _ := os.ReadFile(filepath.Join(root, testkit.EvidenceName(t.Name())+"-reference.log"))
			t.Fatalf("reference exited before ready: port=%d error=%v log=%s", port, waitErr, data)
		default:
		}
		var c io.Closer
		if network == "udp" {
			c, e = net.ListenPacket(network, fmt.Sprintf("127.0.0.1:%d", port))
		} else {
			c, e = net.Listen(network, fmt.Sprintf("127.0.0.1:%d", port))
		}
		if e != nil && addressInUse(e) {
			return cmd
		}
		c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("reference bind timeout")
	return nil
}

func sqFreePort(t *testing.T, network string) int {
	t.Helper()
	return testkit.PeerPort(t, network)
}

func sqSOCKS(proxy int, cmd byte, dst access.Endpoint) (net.Conn, access.Endpoint, error) {
	c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxy), time.Second)
	if e != nil {
		return nil, access.Endpoint{}, e
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		return nil, access.Endpoint{}, e
	}
	var a [2]byte
	if _, e = io.ReadFull(c, a[:]); e != nil || a != [2]byte{5, 0} {
		return nil, access.Endpoint{}, fmt.Errorf("SOCKS auth: %w", e)
	}
	b, e := address.MarshalSOCKS(dst)
	if e != nil {
		return nil, access.Endpoint{}, e
	}
	if _, e = c.Write(append([]byte{5, cmd, 0}, b...)); e != nil {
		return nil, access.Endpoint{}, e
	}
	var h [3]byte
	if _, e = io.ReadFull(c, h[:]); e != nil || h != [3]byte{5, 0, 0} {
		return nil, access.Endpoint{}, fmt.Errorf("SOCKS command: %w", e)
	}
	reply, e := address.ReadSOCKS(c)
	if e != nil {
		return nil, reply, e
	}
	ok = true
	return c, reply, nil
}

type sqSOCKSPacket struct {
	net.PacketConn
	control net.Conn
	relay   net.Addr
}

func (p *sqSOCKSPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	dst, e := netaddr.From(a)
	if e != nil {
		return 0, e
	}
	h, e := address.MarshalSOCKS(dst)
	if e != nil {
		return 0, e
	}
	n, e := p.PacketConn.WriteTo(append(append([]byte{0, 0, 0}, h...), b...), p.relay)
	if e != nil {
		return 0, e
	}
	if n != len(h)+3+len(b) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

func (p *sqSOCKSPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	n, _, e := p.PacketConn.ReadFrom(buf)
	if e != nil {
		return 0, nil, e
	}
	if n < 3 || !bytes.Equal(buf[:3], []byte{0, 0, 0}) {
		return 0, nil, fmt.Errorf("SOCKS UDP header")
	}
	r := bytes.NewReader(buf[3:n])
	dst, e := address.ReadSOCKS(r)
	if e != nil {
		return 0, nil, e
	}
	data := buf[n-r.Len() : n]
	return copy(b, data), netaddr.UDP(dst), nil
}
func (p *sqSOCKSPacket) Close() error { _ = p.control.Close(); return p.PacketConn.Close() }
func sqSOCKSUDP(proxy int) (net.PacketConn, error) {
	ctrl, dst, e := sqSOCKS(proxy, 3, access.Endpoint{Host: "0.0.0.0"})
	if e != nil {
		return nil, e
	}
	if dst.Host == "0.0.0.0" || dst.Host == "::" {
		dst.Host = "127.0.0.1"
	}
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		ctrl.Close()
		return nil, e
	}
	return &sqSOCKSPacket{PacketConn: p, control: ctrl, relay: netaddr.UDP(dst)}, nil
}

func TestShadowQUICPinnedReference(t *testing.T) {
	if os.Getenv("SPLICORE_SHADOWQUIC_REFERENCE") == "" {
		t.Skip("explicit pinned ShadowQUIC reference campaign required")
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(testfixture.TCP(t).Addr())
	// localhost resolves to A and AAAA on Windows. Reserve both families on
	// one owned port rather than assuming the system resolver chooses IPv4.
	udp := shadowsocksUDPFixtureAt(t, "::")
	udp.Host = "127.0.0.1"
	answers, err := net.LookupIP("localhost")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("domain UDP target port=%d DNS answers=%v; real echo owns both families", udp.Port, answers)
	// Real IPv6 target sockets, independently of QUIC carrier address family.
	tcp6, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcp6.Close()
	go func() {
		for {
			c, e := tcp6.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	udp6, e := net.ListenPacket("udp6", "[::1]:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp6.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, e := udp6.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = udp6.WriteTo(b[:n], a)
		}
	}()
	for _, overStream := range []bool{false, true} {
		t.Run(fmt.Sprintf("CMD4_%t", overStream), func(t *testing.T) {
			for _, direction := range []string{"NativeClientReferenceServer", "ReferenceClientNativeServer", "NativeClientNativeServer"} {
				t.Run(direction, func(t *testing.T) {
					var dial func(context.Context, access.Endpoint) (net.Conn, error)
					var packet func(context.Context, access.Endpoint) (net.PacketConn, error)
					var refProcess *exec.Cmd
					var refConfig string
					var h *shadowQUICHandle
					var in ports.RuntimeIntent
					if direction != "NativeClientReferenceServer" {
						h, in = sqServer(t, ctx)
					} else {
						in = testfixture.MieruIntent(t, "udp")
						in.Inbound.Protocol = module.Key()
						in.Credentials[0].Payload = access.UsernamePasswordPayload{Username: secret.New(sqUser), Password: secret.New(sqPass)}
						p := int(in.Inbound.Listeners[0].Endpoint.Port)
						refConfig = fmt.Sprintf("inbounds:\n- type: shadowquic\n  tag: peer\n  bind-addr: 127.0.0.1:%d\n  users:\n  - username: %s\n    password: %s\n  server-name: %s\n  jls-upstream:\n    addr: 127.0.0.1:9\n  zero-rtt: false\n  congestion-control: cubic\noutbounds:\n- type: direct\n  tag: direct\nlog-level: error\n", p, sqUser, sqPass, sqName)
						refProcess = sqReference(t, refConfig, p, "udp")
					}
					var native ports.ClientDialer
					if direction == "ReferenceClientNativeServer" {
						proxy := sqFreePort(t, "tcp")
						sqReference(t, fmt.Sprintf("inbounds:\n- type: socks\n  tag: socks\n  bind-addr: 127.0.0.1:%d\noutbounds:\n- type: shadowquic\n  tag: peer\n  addr: %s\n  username: %s\n  password: %s\n  server-name: %s\n  zero-rtt: false\n  over-stream: %t\n  congestion-control: cubic\nlog-level: error\n", proxy, module.Address(in.Inbound.Listeners[0].Endpoint), sqUser, sqPass, sqName, overStream), proxy, "tcp")
						dial = func(_ context.Context, dst access.Endpoint) (net.Conn, error) {
							c, _, e := sqSOCKS(proxy, 1, dst)
							return c, e
						}
						packet = func(context.Context, access.Endpoint) (net.PacketConn, error) { return sqSOCKSUDP(proxy) }
					} else {
						n, c := sqNode(t, in, 0)
						n.Options.Data = []byte(fmt.Sprintf(`{"handshake_timeout":1,"idle_timeout":10,"keepalive":1,"udp_over_stream":%t}`, overStream))
						native, e = (ShadowQUICOutboundFactory{}).Build(ctx, n, c)
						if e != nil {
							t.Fatal(e)
						}
						defer native.Close()
						dial = native.DialContext
						packet = native.(ports.ClientPacketDialer).ListenPacket
					}
					tests := []struct {
						name string
						dst  access.Endpoint
						size int
					}{{"TCPIPv4Small", tcp, 1}, {"TCPIPv6Boundary", netaddrEndpoint(tcp6.Addr()), 1200}, {"TCPDomainLarge", access.Endpoint{Host: "localhost", Port: tcp.Port}, 2 << 20}, {"TCPMultiwriteHalfClose", tcp, 65536}}
					for _, tc := range tests {
						t.Run(tc.name, func(t *testing.T) {
							c, e := dial(ctx, tc.dst)
							if e != nil {
								t.Fatal(e)
							}
							if e = sqExchange(c, tc.size, true); e != nil {
								t.Fatal(e)
							}
						})
					}
					t.Run("TCP32ConcurrentStreams", func(t *testing.T) {
						var wg sync.WaitGroup
						for i := range 32 {
							wg.Go(func() {
								c, e := dial(ctx, tcp)
								if e != nil {
									t.Error(e)
									return
								}
								if e = sqExchange(c, 4096+i, true); e != nil {
									t.Error(e)
								}
							})
						}
						wg.Wait()
					})
					t.Run("StreamResetIsolation", func(t *testing.T) {
						c, e := dial(ctx, tcp)
						if e != nil {
							t.Fatal(e)
						}
						c.Close()
						c, e = dial(ctx, tcp)
						if e != nil {
							t.Fatal(e)
						}
						if e = sqExchange(c, 77, true); e != nil {
							t.Fatal(e)
						}
					})
					for _, tc := range []struct {
						name string
						dst  access.Endpoint
					}{{"UDPIPv4Boundaries", udp}, {"UDPIPv6", netaddrEndpoint(udp6.LocalAddr())}, {"UDPDomainPreservation", access.Endpoint{Host: "localhost", Port: udp.Port}}} {
						t.Run(tc.name, func(t *testing.T) {
							p, e := packet(ctx, tc.dst)
							if e != nil {
								t.Fatal(e)
							}
							if e = sqUDPExchange(p, tc.dst, []int{0, 1, 1199, 1200}); e != nil {
								t.Fatal(e)
							}
						})
					}
					t.Run("UDPConcurrentAssociations", func(t *testing.T) {
						var wg sync.WaitGroup
						for range 8 {
							wg.Go(func() {
								p, e := packet(ctx, udp)
								if e != nil {
									t.Error(e)
									return
								}
								if e = sqUDPExchange(p, udp, []int{32}); e != nil {
									t.Error(e)
								}
							})
						}
						wg.Wait()
					})
					for _, tc := range []struct {
						name string
						dst  access.Endpoint
					}{{"ClosedTarget", access.Endpoint{Host: "127.0.0.1", Port: 1}}, {"DNSNXDOMAIN", access.Endpoint{Host: "nonexistent.invalid", Port: 80}}} {
						t.Run(tc.name, func(t *testing.T) {
							c, e := dial(ctx, tc.dst)
							if e != nil {
								return
							}
							defer c.Close()
							_ = c.SetDeadline(time.Now().Add(2 * time.Second))
							_, _ = c.Write([]byte{1})
							var b [1]byte
							if _, e = c.Read(b[:]); e == nil {
								t.Fatal("negative target accepted")
							}
						})
					}

					t.Run("CancelCloseCleanup", func(t *testing.T) {
						st, e := dial(ctx, tcp)
						if e != nil {
							t.Fatal(e)
						}
						result := make(chan error, 1)
						go func() { var b [1]byte; _, e := st.Read(b[:]); result <- e }()
						st.Close()
						select {
						case e = <-result:
							if e == nil {
								t.Fatal("close did not wake read")
							}
						case <-time.After(time.Second):
							t.Fatal("close blocked")
						}
					})
					reconnectOwner := t
					t.Run("ConnectionCloseReconnect", func(t *testing.T) {
						if h != nil {
							_ = h.Close(ctx)
							prepared, e := (ShadowQUICCompiler{}).Compile(ctx, in)
							if e != nil {
								t.Fatal(e)
							}
							next := prepared.(*shadowQUICHandle)
							if e = next.Start(ctx); e != nil {
								t.Fatal(e)
							}
							next.Activate()
							h = next
							reconnectOwner.Cleanup(func() { _ = next.Close(context.Background()) })
						} else {
							_ = refProcess.Process.Kill()
							_ = refProcess.Wait()
							refProcess = sqReference(reconnectOwner, refConfig, int(in.Inbound.Listeners[0].Endpoint.Port), "udp")
						}
						var last error
						deadline := time.Now().Add(16 * time.Second)
						for time.Now().Before(deadline) {
							st, e := dial(ctx, tcp)
							if e == nil {
								last = sqExchange(st, 11, true)
								if last == nil {
									return
								}
							} else {
								last = e
							}
							time.Sleep(30 * time.Millisecond)
						}
						t.Fatal("reconnect", last)
					})
					t.Run("UDPOversizeRejected", func(t *testing.T) {
						p, e := packet(ctx, udp)
						if e != nil {
							t.Fatal(e)
						}
						defer p.Close()
						_ = p.SetDeadline(time.Now().Add(250 * time.Millisecond))
						_, e = p.WriteTo(make([]byte, 1201), netaddr.UDP(udp))
						if e == nil {
							var b [1500]byte
							if _, _, e = p.ReadFrom(b[:]); e == nil {
								t.Fatal("oversize accepted")
							}
						}
					})

					t.Run("MalformedCommandAddressAndDatagrams", func(t *testing.T) {
						callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
						defer cancel()
						socket, e := net.ListenPacket("udp4", "127.0.0.1:0")
						if e != nil {
							t.Fatal(e)
						}
						defer socket.Close()
						tr := &quic.Transport{Conn: socket}
						defer tr.Close()
						q, e := tr.Dial(callCtx, netaddr.UDP(in.Inbound.Listeners[0].Endpoint), &tls.Config{ServerName: sqName, NextProtos: []string{"h3"}, SessionTicketsDisabled: true, JLSConfig: &tls.JLSConfig{Enable: true, User: tls.JLSUser{Username: sqUser, Password: sqPass}}}, &quic.Config{Versions: []quic.Version{quic.Version1}, EnableDatagrams: true})
						if e != nil {
							t.Fatal(e)
						}
						defer q.CloseWithError(0, "")
						for _, raw := range [][]byte{{0}, {1, 9}, {1, 3, 0, 0, 80}} {
							st, e := q.OpenStreamSync(callCtx)
							if e != nil {
								t.Fatal(e)
							}
							_ = st.SetDeadline(time.Now().Add(500 * time.Millisecond))
							_, _ = st.Write(raw)
							_ = st.Close()
							var b [1]byte
							if _, e = st.Read(b[:]); e == nil {
								t.Fatal("malformed dispatched")
							}
							st.CancelRead(0)
						}
						_ = q.SendDatagram([]byte{0})
						_ = q.SendDatagram([]byte{255, 255, 42})
						st, e := q.OpenStreamSync(callCtx)
						if e != nil {
							t.Fatal(e)
						}
						_ = st.SetDeadline(time.Now().Add(time.Second))
						header, _ := address.MarshalSOCKS(tcp)
						if _, e = st.Write(append(append([]byte{1}, header...), 42)); e != nil {
							t.Fatal(e)
						}
						var b [1]byte
						if _, e = io.ReadFull(st, b[:]); e != nil || b[0] != 42 {
							t.Fatal("malformed poisoned session", e)
						}
						_ = st.Close()
						st.CancelRead(0)
					})
					t.Run("WrongCredentialsAndServerName", func(t *testing.T) {
						for _, which := range []string{"password", "username", "server-name"} {
							t.Run(which, func(t *testing.T) {
								u, p, name := sqUser, sqPass, sqName
								switch which {
								case "password":
									p = "invalid-synthetic-password"
								case "username":
									u = "invalid-synthetic-username"
								case "server-name":
									name = "wrong.test"
								}
								if direction == "ReferenceClientNativeServer" {
									proxy := sqFreePort(t, "tcp")
									sqReference(t, fmt.Sprintf("inbounds:\n- type: socks\n  tag: socks\n  bind-addr: 127.0.0.1:%d\noutbounds:\n- type: shadowquic\n  tag: peer\n  addr: %s\n  username: %s\n  password: %s\n  server-name: %s\n  zero-rtt: false\nlog-level: error\n", proxy, module.Address(in.Inbound.Listeners[0].Endpoint), u, p, name), proxy, "tcp")
									st, _, e := sqSOCKS(proxy, 1, tcp)
									if e != nil {
										return
									}
									defer st.Close()
									_ = st.SetDeadline(time.Now().Add(2 * time.Second))
									_, _ = st.Write([]byte{1})
									var b [1]byte
									if _, e = st.Read(b[:]); e == nil {
										t.Fatal("unauthorized peer")
									}
								} else {
									n, c := sqNode(t, in, 0)
									c.Payload = access.UsernamePasswordPayload{Username: secret.New(u), Password: secret.New(p)}
									n.Security.TLS.ServerName = name
									bad, e := (ShadowQUICOutboundFactory{}).Build(ctx, n, c)
									if e != nil {
										t.Fatal(e)
									}
									defer bad.Close()
									if st, e := bad.DialContext(ctx, tcp); e == nil {
										st.Close()
										t.Fatal("unauthorized peer")
									}
								}
							})
						}
					})
					if h != nil {
						t.Run("AbruptPeerClose", func(t *testing.T) {
							c, e := dial(ctx, tcp)
							if e != nil {
								t.Fatal(e)
							}
							defer c.Close()
							h.Close(ctx)
							_ = c.SetReadDeadline(time.Now().Add(time.Second))
							var b [1]byte
							if _, e = c.Read(b[:]); e == nil {
								t.Fatal("peer close missing")
							}
						})
					}
				})
			}
		})
	}
}
