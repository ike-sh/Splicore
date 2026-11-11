package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	sm "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
)

func snellV5Client(t *testing.T, ctx context.Context, in ports.RuntimeIntent, version int) *snellDialer {
	t.Helper()
	id, _ := identity.NewID()
	c := in.Credentials[0]
	c.OwnerAccountID = nil
	c.OwnerNodeID = &id
	n := client.RemoteNode{ID: id, Name: "phase35", Protocol: sm.Key(version), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: c.ID, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: []byte(fmt.Sprintf(`{"version":%d}`, version))}}
	d, err := (SnellOutboundFactory{}).Build(ctx, n, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d.(*snellDialer)
}

func snellV5Reference(t *testing.T, endpoint access.Endpoint) {
	t.Helper()
	bin := os.Getenv("SPLICORE_SNELL_V5_REFERENCE")
	if bin == "" {
		t.Skip("explicit pinned official Snell v5 oracle required")
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != "5b2e221f2c6e29b1db8e47053e1221be29d5627da807cb932b089f514a3609f0" {
		t.Fatal("official Snell binary digest")
	}
	root := os.Getenv("SPLICORE_SNELL_V5_EVIDENCE")
	if root == "" {
		root = t.TempDir()
	}
	root = filepath.Join(root, testkit.EvidenceName(t.Name()))
	if err = os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "official.conf")
	if err = os.WriteFile(conf, []byte(fmt.Sprintf("[snell-server]\nlisten = %s\npsk = SyntheticNativeSnell12345\nipv6 = true\n", net.JoinHostPort(endpoint.Host, portString(endpoint.Port)))), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(root, "official.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-c", conf, "-l", "trace")
	cmd.Stdout, cmd.Stderr = f, f
	if err = cmd.Start(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = f.Close() })
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		b, _ := os.ReadFile(filepath.Join(root, "official.log"))
		if bytes.Contains(b, []byte("Start snell quic proxy server")) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("official listener not ready")
}

func snellV5Initial() []byte {
	p := make([]byte, 1200)
	p[0] = 0xc0
	binary.BigEndian.PutUint32(p[1:], 1)
	p[5] = 8
	copy(p[6:14], "dest-cid")
	p[14] = 8
	copy(p[15:23], "src--cid")
	binary.BigEndian.PutUint16(p[24:], 0x4000|1174)
	return p
}

func snellV5Echo(t *testing.T, host string, port int) access.Endpoint {
	t.Helper()
	p, err := net.ListenPacket("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		if runtime.GOOS == "windows" && port == 443 && addressInUse(err) && os.Getenv("GITHUB_ACTIONS") == "" {
			t.Skipf("NOT EXECUTED: this Windows host cannot reserve UDP/443 for the echo fixture (%v); hosted release qualification must execute it", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := p.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = p.WriteTo(b[:n], a)
		}
	}()
	return netaddrEndpoint(p.LocalAddr())
}

func TestSnellV5NativeAndOfficial(t *testing.T) {
	for _, official := range []bool{false, true} {
		t.Run(fmt.Sprintf("Official_%t", official), func(t *testing.T) {
			if official && os.Getenv("SPLICORE_SNELL_V5_REFERENCE") == "" {
				t.Skip("official oracle not configured")
			}
			ctx, in, h := ownedSnell(t, 5)
			if official {
				if err := h.Close(ctx); err != nil {
					t.Fatal(err)
				}
				snellV5Reference(t, in.Inbound.Listeners[0].Endpoint)
			}
			d := snellV5Client(t, ctx, in, 5)
			tcp := netaddrEndpoint(testfixture.TCP(t).Addr())
			for _, version := range []int{4, 5} {
				t.Run(fmt.Sprintf("TCPVersion%d", version), func(t *testing.T) {
					c, err := snellV5Client(t, ctx, in, version).DialContext(ctx, tcp)
					if err != nil {
						t.Fatal(err)
					}
					if err = sqExchangeCompatible(c, 1<<20); err != nil {
						t.Fatal(err)
					}
				})
			}
			for _, host := range []string{"127.0.0.1", "::1"} {
				t.Run(host, func(t *testing.T) {
					dst := snellV5Echo(t, host, 0)
					for _, quic := range []bool{false, true} {
						t.Run(fmt.Sprintf("QUIC_%t", quic), func(t *testing.T) {
							p, err := d.ListenPacket(ctx, dst)
							if err != nil {
								t.Fatal(err)
							}
							defer p.Close()
							_ = p.SetDeadline(time.Now().Add(5 * time.Second))
							payloads := [][]byte{[]byte("ordinary-UDP")}
							if quic {
								payloads = [][]byte{snellV5Initial()}
								for _, size := range []int{1200, 1472, 2048, 8192, 64000} {
									payload := bytes.Repeat([]byte{0x40}, size)
									payloads = append(payloads, payload)
								}
							}
							for _, want := range payloads {
								if _, err = p.WriteTo(want, nil); err != nil {
									t.Fatal(err)
								}
								got := make([]byte, 65535)
								n, _, err := p.ReadFrom(got)
								if err != nil || !bytes.Equal(got[:n], want) {
									t.Fatal("UDP payload", len(want), err)
								}
							}
							selected := p.(*snellV5Packet)
							selected.mu.Lock()
							_, raw := selected.child.(*snellRawPacket)
							selected.mu.Unlock()
							if raw != quic {
								t.Fatal("wrong carrier", raw, quic)
							}
						})
					}
					var wg sync.WaitGroup
					for range 12 {
						wg.Go(func() {
							p, err := d.ListenPacket(ctx, dst)
							if err != nil {
								t.Error(err)
								return
							}
							defer p.Close()
							_ = p.SetDeadline(time.Now().Add(5 * time.Second))
							want := snellV5Initial()
							if _, err = p.WriteTo(want, nil); err != nil {
								t.Error(err)
								return
							}
							b := make([]byte, 1500)
							n, _, err := p.ReadFrom(b)
							if err != nil || !bytes.Equal(b[:n], want) {
								t.Error("concurrent QUIC", err)
							}
						})
					}
					wg.Wait()
				})
			}
			t.Run("AuthenticationAndIsolation", func(t *testing.T) {
				dst := snellV5Echo(t, "127.0.0.1", 0)
				ep := in.Inbound.Listeners[0].Endpoint
				raw, err := net.Dial("udp", net.JoinHostPort(ep.Host, portString(ep.Port)))
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				wrong, _ := wire.NewKey(5, "WrongSyntheticPassword")
				bad, _ := wire.ProtectQUIC(wrong, dst, snellV5Initial())
				good, _ := wire.ProtectQUIC(d.key, dst, snellV5Initial())
				tampered := bytes.Clone(good)
				tampered[len(tampered)-1] ^= 1
				for _, invalid := range [][]byte{{0x40}, {0}, {1, 2, 3}, bad, tampered} {
					_ = raw.SetDeadline(time.Now().Add(80 * time.Millisecond))
					_, _ = raw.Write(invalid)
					if _, err = raw.Read(make([]byte, 1500)); err == nil {
						t.Fatal("invalid handshake forwarded")
					}
				}
				_ = raw.SetDeadline(time.Now().Add(time.Second))
				_, _ = raw.Write(good)
				got := make([]byte, 1500)
				n, err := raw.Read(got)
				if err != nil || !bytes.Equal(got[:n], snellV5Initial()) {
					t.Fatal("negative input poisoned healthy sibling", err)
				}
			})
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			if !official {
				native := h.(*Handle)
				if err := h.Close(ctx); err != nil {
					t.Fatal(err)
				}
				native.quicProxy.mu.Lock()
				count := len(native.quicProxy.flows)
				native.quicProxy.mu.Unlock()
				if count != 0 || h.Stats().Active != 0 {
					t.Fatal("retained QUIC resources", count)
				}
				p, err := net.ListenPacket("udp", net.JoinHostPort(in.Inbound.Listeners[0].Endpoint.Host, portString(in.Inbound.Listeners[0].Endpoint.Port)))
				if err != nil {
					t.Fatal("UDP listener retained", err)
				}
				_ = p.Close()
			}
		})
	}
}

// Concurrent read/write is required to exercise bounded record buffering.
func sqExchangeCompatible(c net.Conn, size int) error {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	want := bytes.Repeat([]byte{42}, size)
	done := make(chan error, 1)
	go func() {
		_, err := c.Write(want)
		if err == nil {
			err = c.(interface{ CloseWrite() error }).CloseWrite()
		}
		done <- err
	}()
	got, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if err = <-done; err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("TCP corruption")
	}
	return nil
}

func TestSnellV5IPv6UnderlayAndUDP443(t *testing.T) {
	for _, official := range []bool{false, true} {
		t.Run(fmt.Sprint(official), func(t *testing.T) {
			ctx, in, old := ownedSnellAt(t, 5, "::1")
			_ = old.Close(ctx)
			if official {
				snellV5Reference(t, in.Inbound.Listeners[0].Endpoint)
			} else {
				p, err := (SnellCompiler{}).Compile(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				h := p.(ports.RuntimeHandle)
				defer h.Close(ctx)
				if err = h.Start(ctx); err != nil {
					t.Fatal(err)
				}
				h.Activate()
			}
			d := snellV5Client(t, ctx, in, 5)
			for _, quic := range []bool{false, true} {
				dst := snellV5Echo(t, "::1", map[bool]int{false: 443, true: 0}[quic])
				p, err := d.ListenPacket(ctx, dst)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				_ = p.SetDeadline(time.Now().Add(3 * time.Second))
				want := []byte("non QUIC UDP on port 443")
				if quic {
					want = snellV5Initial()
				}
				if _, err = p.WriteTo(want, nil); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 1500)
				n, _, err := p.ReadFrom(b)
				if err != nil || !bytes.Equal(b[:n], want) {
					t.Fatal("IPv6 underlay payload", err)
				}
				selected := p.(*snellV5Packet)
				selected.mu.Lock()
				_, raw := selected.child.(*snellRawPacket)
				selected.mu.Unlock()
				if raw != quic {
					t.Fatal("UDP/443 classifier changed path")
				}
			}
		})
	}
}

func TestSnellV5UDPBindRollbackAndActiveClose(t *testing.T) {
	ctx, in, old := ownedSnell(t, 5)
	_ = old.Close(ctx)
	ep := in.Inbound.Listeners[0].Endpoint
	addr := net.JoinHostPort(ep.Host, portString(ep.Port))
	occupied, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := (SnellCompiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := p.(ports.RuntimeHandle)
	defer h.Close(ctx)
	if h.Start(ctx) == nil {
		t.Fatal("partial listener start succeeded")
	}
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal("TCP listener retained after UDP conflict", err)
	}
	_ = tcp.Close()
	_ = occupied.Close()
	if err = h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	d := snellV5Client(t, ctx, in, 5)
	packet, err := d.ListenPacket(ctx, snellV5Echo(t, "127.0.0.1", 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = packet.WriteTo(snellV5Initial(), nil); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1500)
	if _, _, err = packet.ReadFrom(b); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := packet.ReadFrom(b); done <- err }()
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read survived Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close retained active read")
	}
	if err = h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	native := h.(*Handle)
	native.quicProxy.mu.Lock()
	count := len(native.quicProxy.flows)
	native.quicProxy.mu.Unlock()
	if count != 0 {
		t.Fatal("active close retained server flow")
	}
}

func TestSnellV5RecordTraffic(t *testing.T) {
	for _, official := range []bool{false, true} {
		t.Run(fmt.Sprint(official), func(t *testing.T) {
			ctx, in, h := ownedSnell(t, 5)
			if official {
				_ = h.Close(ctx)
				snellV5Reference(t, in.Inbound.Listeners[0].Endpoint)
			}
			d := snellV5Client(t, ctx, in, 5)
			dst := netaddrEndpoint(testfixture.TCP(t).Addr())
			// Small interactive exchanges require a reply before the next submission.
			c, err := d.DialContext(ctx, dst)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(45 * time.Second))
			for i := range 64 {
				want := bytes.Repeat([]byte{byte(i)}, 1+i*7)
				if _, err = c.Write(want); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(want))
				if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
					t.Fatal("interactive corruption", err)
				}
			}
			_ = c.Close()
			// Long stream and concurrent bulk writes cross every DRS transition.
			var wg sync.WaitGroup
			for i := range 5 {
				wg.Go(func() {
					c, err := d.DialContext(ctx, dst)
					if err != nil {
						t.Error(err)
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(60 * time.Second))
					size := 4 << 20
					if i == 0 {
						size = 16 << 20
					}
					want := bytes.Repeat([]byte{byte(i + 1)}, size)
					done := make(chan error, 1)
					go func() {
						_, err := c.Write(want)
						if err == nil {
							err = c.(interface{ CloseWrite() error }).CloseWrite()
						}
						done <- err
					}()
					got, err := io.ReadAll(c)
					if err != nil || !bytes.Equal(got, want) {
						t.Error("bulk corruption/truncation", i, len(got), err)
					}
					if err = <-done; err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
		})
	}
}

func TestSnellV5DeadlineDuringAdmission(t *testing.T) {
	ctx, in, _ := ownedSnell(t, 5)
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := blocked.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	d := snellV5Client(t, ctx, in, 5)
	d.endpoint = netaddrEndpoint(blocked.Addr())
	pc, err := d.ListenPacket(ctx, access.Endpoint{Host: "127.0.0.1", Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetWriteDeadline(time.Now().Add(time.Minute))
	done := make(chan error, 1)
	go func() { _, err := pc.WriteTo([]byte("ordinary UDP"), nil); done <- err }()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(time.Second):
		t.Fatal("admission did not start")
	}
	_ = pc.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expired admission succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("updated deadline retained handshake")
	}
	read := make(chan error, 1)
	go func() { _, _, err := pc.ReadFrom(make([]byte, 32)); read <- err }()
	_ = pc.Close()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("closed unselected read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("unselected read retained")
	}
}
