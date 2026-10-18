//go:build linux

package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/hysteria2/backend"
)

type hyIngressEvent struct {
	At     time.Time `json:"timestamp"`
	Port   int       `json:"destination_port"`
	Source string    `json:"source"`
}
type hyIngress struct {
	sockets []net.PacketConn
	up      net.PacketConn
	mu      sync.Mutex
	last    net.Addr
	via     net.PacketConn
	events  []hyIngressEvent
	wg      sync.WaitGroup
}

// Every public port remains actually bound throughout the test. One upstream
// source socket models destination NAT while preserving the logical QUIC peer.
func hyNewIngress(t *testing.T, remote net.Addr, reorder bool, boundaryHost string) (*hyIngress, string) {
	t.Helper()
	r := &hyIngress{}
	var e error
	r.up, e = net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var ports []string
	var reorderMu sync.Mutex
	var held []byte
	var seen int
	listenPorts := []string{"0", "0", "0", "0"}
	host := "127.0.0.1"
	if boundaryHost != "" {
		host = boundaryHost
		listenPorts = []string{"65534", "65535"}
	}
	for _, listenPort := range listenPorts {
		p, e := net.ListenPacket("udp", net.JoinHostPort(host, listenPort))
		if e != nil {
			t.Fatal(e)
		}
		r.sockets = append(r.sockets, p)
		port := p.LocalAddr().(*net.UDPAddr).Port
		ports = append(ports, strconv.Itoa(port))
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			b := make([]byte, 65535)
			for {
				n, a, e := p.ReadFrom(b)
				if e != nil {
					return
				}
				r.mu.Lock()
				r.last, r.via = a, p
				r.events = append(r.events, hyIngressEvent{time.Now().UTC(), port, a.String()})
				r.mu.Unlock()
				reorderMu.Lock()
				if reorder && seen == 0 {
					held = bytes.Clone(b[:n])
					seen++
					reorderMu.Unlock()
					continue
				}
				if reorder && seen == 1 {
					r.up.WriteTo(b[:n], remote)
					r.up.WriteTo(held, remote)
					held = nil
					seen++
					reorderMu.Unlock()
					continue
				}
				reorderMu.Unlock()
				r.up.WriteTo(b[:n], remote)
			}
		}()
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		b := make([]byte, 65535)
		for {
			n, _, e := r.up.ReadFrom(b)
			if e != nil {
				return
			}
			r.mu.Lock()
			a, p := r.last, r.via
			r.mu.Unlock()
			if p != nil {
				p.WriteTo(b[:n], a)
			}
		}
	}()
	t.Cleanup(func() {
		for _, p := range r.sockets {
			p.Close()
		}
		r.up.Close()
		r.wg.Wait()
	})
	if boundaryHost != "" {
		return r, "65534-65535"
	}
	return r, strings.Join(ports, ",")
}
func (r *hyIngress) snapshot() []hyIngressEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hyIngressEvent(nil), r.events...)
}

func hyCompletenessServer(t *testing.T, obfs *cfg.HysteriaObfs, tuning ...cfg.QUIC) (*backend.Server, *tls.Config, *atomic.Int64) {
	t.Helper()
	material := testkit.TLS(t)
	cert, e := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(material.CACertificate))
	clientTLS := &tls.Config{RootCAs: pool, ServerName: material.ServerName, NextProtos: []string{"h3"}}
	p, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	admitted := &atomic.Int64{}
	var q cfg.QUIC
	if len(tuning) > 0 {
		q = tuning[0]
	}
	s, e := backend.NewServer(context.Background(), p, backend.ServerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Transport: cfg.Hysteria{Version: 2, Obfs: obfs, QUIC: q}, Authenticate: func(password string) (string, bool) {
		if password == "SyntheticCompletenessPassword" || password == "SyntheticCompletenessSecondUser" {
			admitted.Add(1)
			return password, true
		}
		return "", false
	}, TCP: func(ctx context.Context, id string, c *backend.Stream, dst access.Endpoint) error {
		defer c.Close()
		if e := c.Reply(true); e != nil {
			return e
		}
		_, e := io.Copy(c, c)
		return e
	}, UDP: func(ctx context.Context, id string, p net.PacketConn) error {
		defer p.Close()
		b := make([]byte, 8192)
		for {
			n, a, e := p.ReadFrom(b)
			if e != nil {
				return e
			}
			if _, e = p.WriteTo(b[:n], a); e != nil {
				return e
			}
		}
	}})
	if e != nil {
		t.Fatal(e)
	}
	s.Start()
	t.Cleanup(func() {
		if e := s.Close(context.Background()); e != nil {
			t.Error(e)
		}
	})
	return s, clientTLS, admitted
}
func hyCompletenessClient(t *testing.T, remote net.Addr, tc *tls.Config, h cfg.Hysteria) (*backend.Client, *atomic.Int64) {
	t.Helper()
	sockets := &atomic.Int64{}
	c, e := backend.NewClient(context.Background(), backend.ClientConfig{TLS: tc, Password: "SyntheticCompletenessPassword", Transport: h, Socket: func(context.Context) (net.PacketConn, net.Addr, error) {
		sockets.Add(1)
		p, e := net.ListenPacket("udp", "127.0.0.1:0")
		return p, remote, e
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c, sockets
}
func TestNativeHysteriaCompletenessNegativeMatrix(t *testing.T) {
	sam := &cfg.HysteriaObfs{Type: "salamander", Password: "SyntheticObfsPassword"}
	gecko := &cfg.HysteriaObfs{Type: "gecko", Password: sam.Password}
	wrongSam := *sam
	wrongSam.Password = "WrongSyntheticObfsPassword"
	wrongGecko := *gecko
	wrongGecko.Password = wrongSam.Password
	for _, row := range []struct {
		name           string
		client, server *cfg.HysteriaObfs
	}{{"salamander_plain", sam, nil}, {"plain_salamander", nil, sam}, {"salamander_wrong", &wrongSam, sam}, {"gecko_wrong", &wrongGecko, gecko}, {"salamander_gecko", sam, gecko}, {"gecko_salamander", gecko, sam}} {
		t.Run(row.name, func(t *testing.T) {
			s, tc, auth := hyCompletenessServer(t, row.server)
			c, _ := hyCompletenessClient(t, s.Addr(), tc, cfg.Hysteria{Version: 2, Obfs: row.client})
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			stream, e := c.OpenTCP(ctx, access.Endpoint{Host: "127.0.0.1", Port: 1})
			if e == nil {
				stream.Close()
				t.Fatal("mismatch falsely succeeded")
			}
			c.Close()
			if auth.Load() != 0 {
				t.Fatal("plaintext downgrade")
			}
		})
	}
}

func TestNativeHysteriaCompletenessPinnedOfficial(t *testing.T) {
	root := os.Getenv("SPLICORE_HY_COMPLETENESS_EVIDENCE")
	if root == "" {
		t.Skip("explicit pinned completeness reference campaign required")
	}
	ref := os.Getenv("SPLICORE_HYSTERIA_REFERENCE")
	if mkcpSHA(t, ref) != "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691" {
		t.Fatal("official reference pin")
	}
	for kindIndex, kind := range []string{"salamander", "gecko"} {
		for directionIndex, direction := range []string{"SPLICORE_TO_REFERENCE", "REFERENCE_TO_SPLICORE"} {
			for _, policy := range []string{"none", "fixed", "random"} {
				name := kind + "-" + direction + "-" + policy
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					dir := filepath.Join(root, name)
					if e := os.MkdirAll(dir, 0700); e != nil {
						t.Fatal(e)
					}
					obfs := &cfg.HysteriaObfs{Type: kind, Password: "SyntheticCompletenessObfs"}
					refObfs := map[string]any{"type": kind, kind: map[string]any{"password": obfs.Password}}
					if kind == "gecko" && policy != "none" {
						obfs.MinPacketSize, obfs.MaxPacketSize = 512, 768
						refObfs[kind] = map[string]any{"password": obfs.Password, "minPacketSize": 512, "maxPacketSize": 768}
					}
					boundaryHost := ""
					if policy == "fixed" {
						boundaryHost = fmt.Sprintf("127.28.%d.%d", kindIndex+1, directionIndex+1)
					}
					h := cfg.Hysteria{Version: 2, Obfs: obfs}
					var tcp net.Conn
					var udp net.PacketConn
					var udpAddress net.Addr
					var ingress *hyIngress
					var opens, auth *atomic.Int64
					material := testkit.TLS(t)
					cert, _ := os.ReadFile(material.CertificateFile)
					key, _ := os.ReadFile(material.PrivateKeyFile)
					certPath, keyPath, caPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "ca.pem")
					os.WriteFile(certPath, cert, 0600)
					os.WriteFile(keyPath, key, 0600)
					os.WriteFile(caPath, []byte(material.CACertificate), 0600)
					// Official server needs real echo destinations; Splicore fixture echoes in
					// its protocol handlers, preserving TCP stream and UDP session identity.
					l, e := net.Listen("tcp", "127.0.0.1:0")
					if e != nil {
						t.Fatal(e)
					}
					defer l.Close()
					tcpTarget := netaddrEndpoint(l.Addr())
					tcpDone := make(chan struct{})
					go func() {
						defer close(tcpDone)
						for {
							c, e := l.Accept()
							if e != nil {
								return
							}
							go func() { defer c.Close(); io.Copy(c, c) }()
						}
					}()
					t.Cleanup(func() { l.Close(); <-tcpDone })
					echo, e := net.ListenPacket("udp", "127.0.0.1:0")
					if e != nil {
						t.Fatal(e)
					}
					udpTarget := netaddrEndpoint(echo.LocalAddr())
					echoDone := make(chan struct{})
					go func() {
						defer close(echoDone)
						b := make([]byte, 8192)
						for {
							n, a, e := echo.ReadFrom(b)
							if e != nil {
								return
							}
							echo.WriteTo(b[:n], a)
						}
					}()
					t.Cleanup(func() { echo.Close(); <-echoDone })
					if direction == "SPLICORE_TO_REFERENCE" {
						doc := map[string]any{"listen": "127.0.0.1:0", "tls": map[string]any{"cert": certPath, "key": keyPath}, "auth": map[string]any{"type": "password", "password": "SyntheticCompletenessPassword"}, "obfs": refObfs}
						address := hyStart(t, ref, "hysteria", dir, "server", doc, "udp", 0, "127.0.0.1")
						remote, e := net.ResolveUDPAddr("udp", address)
						if e != nil {
							t.Fatal(e)
						}
						if policy == "none" {
							wrong := h.Clone()
							o := *wrong.Obfs
							o.Password = "WrongSyntheticObfs"
							wrong.Obfs = &o
							pool := x509.NewCertPool()
							pool.AppendCertsFromPEM([]byte(material.CACertificate))
							bad, _ := hyCompletenessClient(t, remote, &tls.Config{RootCAs: pool, ServerName: material.ServerName}, wrong)
							ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
							stream, e := bad.OpenTCP(ctx, tcpTarget)
							cancel()
							bad.Close()
							if e == nil {
								stream.Close()
								t.Fatal("official accepted wrong obfs password")
							}
						}
						if policy != "none" {
							var ports string
							ingress, ports = hyNewIngress(t, remote, kind == "gecko", boundaryHost)
							h.UDP = &cfg.HysteriaUDP{Ports: ports}
							if policy == "fixed" {
								h.UDP.HopInterval = 5
							} else {
								h.UDP.MinHopInterval, h.UDP.MaxHopInterval = 5, 6
							}
							remote = ingress.sockets[0].LocalAddr().(*net.UDPAddr)
						}
						pool := x509.NewCertPool()
						pool.AppendCertsFromPEM([]byte(material.CACertificate))
						client, count := hyCompletenessClient(t, remote, &tls.Config{RootCAs: pool, ServerName: material.ServerName}, h)
						opens = count
						tcp, e = client.OpenTCP(context.Background(), tcpTarget)
						if e != nil {
							t.Fatal(e)
						}
						packet, e := client.OpenPacket(context.Background(), udpTarget)
						if e != nil {
							t.Fatal(e)
						}
						udp = packet
						udpAddress = &net.UDPAddr{IP: net.ParseIP(udpTarget.Host), Port: int(udpTarget.Port)}
					} else {
						server, _, admitted := hyCompletenessServer(t, obfs)
						auth = admitted
						if policy == "none" {
							wrong := map[string]any{"server": server.Addr().String(), "auth": "SyntheticCompletenessPassword", "tls": map[string]any{"insecure": true}, "obfs": map[string]any{"type": kind, kind: map[string]any{"password": "WrongSyntheticObfs"}}, "socks5": map[string]any{"listen": "127.0.0.1:0"}}
							path := filepath.Join(dir, "wrong-password-config.json")
							mkcpJSON(t, path, wrong)
							ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
							cmd := exec.CommandContext(ctx, ref, "client", "-c", path, "--disable-update-check")
							output, e := cmd.CombinedOutput()
							timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
							cancel()
							if e == nil || !timedOut || auth.Load() != 0 {
								t.Fatal("wrong reference obfs admitted")
							}
							if e = os.WriteFile(filepath.Join(dir, "wrong-password-reference.log"), output, 0600); e != nil {
								t.Fatal(e)
							}
						}
						serverAddress := server.Addr().String()
						var ports string
						if policy != "none" {
							ingress, ports = hyNewIngress(t, server.Addr(), kind == "gecko", boundaryHost)
							serverAddress = net.JoinHostPort(ingress.sockets[0].LocalAddr().(*net.UDPAddr).IP.String(), ports)
						}
						// Use the fixture's CA generated inside its server helper.
						doc := map[string]any{"server": serverAddress, "auth": "SyntheticCompletenessPassword", "tls": map[string]any{"insecure": true}, "obfs": refObfs, "socks5": map[string]any{"listen": "127.0.0.1:0"}, "udpForwarding": []any{map[string]any{"listen": "127.0.0.1:0", "remote": net.JoinHostPort(udpTarget.Host, strconv.Itoa(int(udpTarget.Port)))}}}
						if policy == "fixed" {
							doc["transport"] = map[string]any{"type": "udp", "udp": map[string]any{"hopInterval": "5s"}}
						} else if policy == "random" {
							doc["transport"] = map[string]any{"type": "udp", "udp": map[string]any{"minHopInterval": "5s", "maxHopInterval": "6s"}}
						}
						socks := hyStart(t, ref, "hysteria", dir, "client", doc, "tcp", 0, "127.0.0.1")
						tcp, _ = hySocks(t, socks, 1, tcpTarget)
						forward, ok := hyOwnedAddress(hyReferencePID(t, dir, "client"), "udp", 0, "127.0.0.1")
						if !ok {
							t.Fatal("forward socket")
						}
						up, e := net.Dial("udp", forward)
						if e != nil {
							t.Fatal(e)
						}
						udp = &hyConnectedPacket{Conn: up}
					}
					defer tcp.Close()
					defer udp.Close()
					var checks []map[string]any
					duration := time.Second
					if policy != "none" {
						duration = 60 * time.Second
					}
					start := time.Now()
					for index := 0; time.Since(start) < duration; index++ {
						payload := bytes.Repeat([]byte(fmt.Sprintf("%s/%04d/", name, index)), 37)
						tcp.SetDeadline(time.Now().Add(3 * time.Second))
						if _, e := tcp.Write(payload); e != nil {
							t.Fatal("TCP survived hop", e)
						}
						reply := make([]byte, len(payload))
						if _, e := io.ReadFull(tcp, reply); e != nil || !bytes.Equal(payload, reply) {
							t.Fatal("TCP integrity", e)
						}
						size := []int{1, 300, 800}[index%3]
						packet := bytes.Repeat([]byte{byte(index), 7, 9}, size)
						udp.SetDeadline(time.Now().Add(3 * time.Second))
						if _, e := udp.WriteTo(packet, udpAddress); e != nil {
							t.Fatal("UDP write", e)
						}
						b := make([]byte, 8192)
						n, _, e := udp.ReadFrom(b)
						if e != nil || !bytes.Equal(packet, b[:n]) {
							t.Fatal("UDP integrity", index, len(packet), e)
						}
						checks = append(checks, map[string]any{"timestamp": time.Now().UTC(), "TCP_sha256": hyBytesHash(payload), "UDP_sha256": hyBytesHash(packet), "TCP_bytes": len(payload), "UDP_bytes": len(packet), "continuous_TCP_stream": true, "continuous_UDP_session": true})
						if policy != "none" && time.Since(start) >= 19*time.Second {
							events := ingress.snapshot()
							changes := 0
							last := 0
							for _, event := range events {
								if last != 0 && event.Port != last {
									changes++
								}
								last = event.Port
							}
							if changes >= 3 {
								break
							}
						}
						time.Sleep(200 * time.Millisecond)
					}
					var events []hyIngressEvent
					var sequence []int
					if ingress != nil {
						events = ingress.snapshot()
						for _, e := range events {
							if len(sequence) == 0 || sequence[len(sequence)-1] != e.Port {
								sequence = append(sequence, e.Port)
							}
						}
						if len(sequence) < 4 {
							t.Fatal("fewer than three observed destination changes", sequence)
						}
					}
					if opens != nil && opens.Load() != 1 {
						t.Fatal("QUIC reconnected", opens.Load())
					}
					if auth != nil && auth.Load() != 1 {
						t.Fatal("repeated auth", auth.Load())
					}
					mkcpJSON(t, filepath.Join(dir, "result.json"), map[string]any{"profile_id": name, "obfs": kind, "direction": direction, "hop_policy": policy, "gecko_initial_fragment_reorder": kind == "gecko" && policy != "none", "result": "PASS", "payloads": checks, "observed_ingress": events, "port_sequence": sequence, "actual_hops": max(0, len(sequence)-1), "continuous_TCP_stream": true, "continuous_UDP_session": true, "native_socket_opens": func() int64 {
						if opens != nil {
							return opens.Load()
						}
						return 0
					}(), "native_authentications": func() int64 {
						if auth != nil {
							return auth.Load()
						}
						return 0
					}(), "reference_sha256": mkcpSHA(t, ref), "validation_binary_sha256": func() string { exe, _ := os.Executable(); return mkcpSHA(t, exe) }()})
				})
			}
		}
	}
}

type hyConnectedPacket struct{ net.Conn }

func TestNativeHysteriaCompletenessNativeComposition(t *testing.T) {
	for _, kind := range []string{"none", "salamander", "gecko"} {
		for _, mode := range []string{"reno", "bbr", "brutal", "force-brutal"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				q := cfg.QUIC{Congestion: mode}
				if mode == "brutal" || mode == "force-brutal" {
					q.BrutalUp, q.BrutalDown = "20mbps", "20mbps"
				}
				obfs := &cfg.HysteriaObfs{Type: kind}
				if kind != "none" {
					obfs.Password = "SyntheticNativeObfs"
				}
				s, tc, auth := hyCompletenessServer(t, obfs, q)
				c, opens := hyCompletenessClient(t, s.Addr(), tc, cfg.Hysteria{Version: 2, Obfs: obfs, QUIC: q})
				dst := access.Endpoint{Host: "127.0.0.1", Port: 1234}
				p, e := c.OpenPacket(context.Background(), dst)
				if e != nil {
					t.Fatal(e)
				}
				defer p.Close()
				p.SetDeadline(time.Now().Add(3 * time.Second))
				for _, size := range []int{1, 900, 2400, 4096} {
					b := bytes.Repeat([]byte{7}, size)
					p.WriteTo(b, nil)
					got := make([]byte, 8192)
					n, _, e := p.ReadFrom(got)
					if e != nil || !bytes.Equal(got[:n], b) {
						t.Fatal(size, n, e)
					}
				}
				for range 4 {
					stream, e := c.OpenTCP(context.Background(), dst)
					if e != nil {
						t.Fatal(e)
					}
					stream.SetDeadline(time.Now().Add(time.Second))
					stream.Write([]byte{7})
					b := make([]byte, 1)
					if _, e = io.ReadFull(stream, b); e != nil || b[0] != 7 {
						t.Fatal(e)
					}
					stream.Close()
				}
				if opens.Load() != 1 || auth.Load() != 1 {
					t.Fatal("unsafe connection reuse")
				}
				states := c.Congestion()
				want := mode
				if want == "force-brutal" {
					want = "brutal"
				}
				if len(states) != 1 || states[0].Selected != want {
					t.Fatal("controller selection", states)
				}
				c.Close()
			})
		}
	}
}

func (c *hyConnectedPacket) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
func (c *hyConnectedPacket) ReadFrom(p []byte) (int, net.Addr, error) {
	n, e := c.Read(p)
	return n, c.RemoteAddr(), e
}

func TestNativeHysteriaCompletenessPinnedOfficialMultiUser(t *testing.T) {
	root := os.Getenv("SPLICORE_HY_COMPLETENESS_EVIDENCE")
	if root == "" {
		t.Skip("explicit pinned completeness reference campaign required")
	}
	ref := os.Getenv("SPLICORE_HYSTERIA_REFERENCE")
	if mkcpSHA(t, ref) != "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691" {
		t.Fatal("reference pin")
	}
	for _, kind := range []string{"salamander", "gecko"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(root, "multi-user-"+kind)
			os.MkdirAll(dir, 0700)
			obfs := &cfg.HysteriaObfs{Type: kind, Password: "SyntheticMultiUserObfs"}
			server, _, auth := hyCompletenessServer(t, obfs)
			var rows []map[string]any
			for index, password := range []string{"SyntheticCompletenessPassword", "SyntheticCompletenessSecondUser"} {
				userDir := filepath.Join(dir, strconv.Itoa(index))
				os.MkdirAll(userDir, 0700)
				doc := map[string]any{"server": server.Addr().String(), "auth": password, "tls": map[string]any{"insecure": true}, "obfs": map[string]any{"type": kind, kind: map[string]any{"password": obfs.Password}}, "socks5": map[string]any{"listen": "127.0.0.1:0"}, "udpForwarding": []any{map[string]any{"listen": "127.0.0.1:0", "remote": "127.0.0.1:1234"}}}
				socks := hyStart(t, ref, "hysteria", userDir, "client", doc, "tcp", 0, "127.0.0.1")
				c, _ := hySocks(t, socks, 1, access.Endpoint{Host: "127.0.0.1", Port: 1234})
				for sequence := range 2 {
					b := bytes.Repeat([]byte{byte(index + sequence + 7)}, 2048)
					c.SetDeadline(time.Now().Add(3 * time.Second))
					c.Write(b)
					got := make([]byte, len(b))
					if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(b, got) {
						t.Fatal("multi-user TCP", e)
					}
					rows = append(rows, map[string]any{"user_index": index, "network": "tcp", "bytes": len(b), "sha256": hyBytesHash(b)})
				}
				c.Close()
				forward, ok := hyOwnedAddress(hyReferencePID(t, userDir, "client"), "udp", 0, "127.0.0.1")
				if !ok {
					t.Fatal("forwarding socket")
				}
				p, e := net.Dial("udp", forward)
				if e != nil {
					t.Fatal(e)
				}
				p.SetDeadline(time.Now().Add(3 * time.Second))
				payloads := hyUDP(t, func(b []byte) error { _, e := p.Write(b); return e }, p.Read, 4048)
				p.Close()
				for _, row := range payloads {
					row["user_index"] = index
					row["network"] = "udp"
					rows = append(rows, row)
				}
			}
			if auth.Load() != 2 {
				t.Fatal("multi-user isolation", auth.Load())
			}
			mkcpJSON(t, filepath.Join(dir, "result.json"), map[string]any{"profile_id": "multi-user-" + kind, "obfs": kind, "direction": "REFERENCE_TO_SPLICORE", "users": 2, "authentications": auth.Load(), "payloads": rows, "result": "PASS", "reference_sha256": mkcpSHA(t, ref)})
		})
	}
}

func TestNativeHysteriaCompletenessConcurrentGeckoAdmission(t *testing.T) {
	o := &cfg.HysteriaObfs{Type: "gecko", Password: "SyntheticConcurrentObfs"}
	s, tc, auth := hyCompletenessServer(t, o)
	clients := make([]*backend.Client, 8)
	for i := range clients {
		clients[i], _ = hyCompletenessClient(t, s.Addr(), tc, cfg.Hysteria{Version: 2, Obfs: o})
	}
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, e := c.OpenTCP(ctx, access.Endpoint{Host: "127.0.0.1", Port: 1234})
			if e != nil {
				t.Error(e)
				return
			}
			defer stream.Close()
			stream.SetDeadline(time.Now().Add(time.Second))
			b := bytes.Repeat([]byte{byte(i)}, 900)
			if _, e = stream.Write(b); e != nil {
				t.Error(e)
				return
			}
			got := make([]byte, len(b))
			if _, e = io.ReadFull(stream, got); e != nil || !bytes.Equal(got, b) {
				t.Error("interleaved handshake/stream", e)
			}
		}()
	}
	wg.Wait()
	if auth.Load() != 8 {
		t.Fatal("admission count", auth.Load())
	}
	// Shut down with every admitted obfuscated connection still active.
	if e := s.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	for _, c := range clients {
		c.Close()
	}
}

func TestNativeHysteriaCompletenessLivePoolIsolation(t *testing.T) {
	o := &cfg.HysteriaObfs{Type: "salamander", Password: "SyntheticPoolObfs"}
	s, tc, auth := hyCompletenessServer(t, o)
	ingress, allPorts := hyNewIngress(t, s.Addr(), false, "")
	first := ingress.sockets[0].LocalAddr()
	settings := cfg.Hysteria{Version: 2, Obfs: o, UDP: &cfg.HysteriaUDP{Ports: strconv.Itoa(first.(*net.UDPAddr).Port), HopInterval: 5}}
	baseline, baseOpens := hyCompletenessClient(t, first, tc, settings)
	exchange := func(c *backend.Client, success bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()
		stream, e := c.OpenTCP(ctx, access.Endpoint{Host: "127.0.0.1", Port: 1234})
		if !success {
			if e == nil {
				stream.Close()
				t.Fatal("incompatible manager borrowed admitted connection")
			}
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		defer stream.Close()
		stream.SetDeadline(time.Now().Add(time.Second))
		if _, e = stream.Write([]byte{7}); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 1)
		if _, e = io.ReadFull(stream, b); e != nil || b[0] != 7 {
			t.Fatal(e)
		}
	}
	exchange(baseline, true)
	for _, variant := range []string{"password", "type", "ports", "policy"} {
		t.Run(variant, func(t *testing.T) {
			h := settings.Clone()
			switch variant {
			case "password":
				h.Obfs.Password = "OtherSyntheticPoolObfs"
			case "type":
				h.Obfs.Type = "gecko"
			case "ports":
				h.UDP.Ports = allPorts
			case "policy":
				h.UDP.HopInterval = 0
				h.UDP.MinHopInterval = 5
				h.UDP.MaxHopInterval = 6
			}
			c, opens := hyCompletenessClient(t, first, tc, h)
			exchange(c, variant == "ports" || variant == "policy")
			if opens.Load() != 1 {
				t.Fatal("manager socket ownership", opens.Load())
			}
			c.Close()
		})
	}
	exchange(baseline, true)
	if baseOpens.Load() != 1 || auth.Load() != 3 {
		t.Fatal("pool isolation", baseOpens.Load(), auth.Load())
	}
}
