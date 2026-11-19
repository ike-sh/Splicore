//go:build with_gvisor

package wireguardendpoint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func xrayPeer(t *testing.T, lease *testkit.DualPeerPort, config map[string]any, networks ...string) int {
	t.Helper()
	pid, _, err := startXrayPeer(t, config, lease.Address(), lease.ReleaseSockets, networks...)
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func startXrayPeer(t *testing.T, config map[string]any, address string, handoff func(), networks ...string) (int, string, error) {
	t.Helper()
	binary := os.Getenv("SPLICORE_PHASE34_XRAY_REFERENCE")
	if binary == "" {
		t.Skip("external Xray WireGuard oracle not configured")
	}
	binaryBytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binaryBytes)
	want := map[string]string{
		"linux/amd64":   "a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e",
		"windows/amd64": "c77a00eb84fb93ae044c2d771a1cabcc033b81e487253fbc35b12df6879c1e15",
		"linux/arm64":   "dc3324f437132d70d29ddadea19b202949c2d1230b5d90dac469b03f68829c8b",
		"windows/arm64": "bf47164a9be92afc87f50f1e22d25730f044222bfd6cedf9a524201379be023f",
	}[runtime.GOOS+"/"+runtime.GOARCH]
	if want == "" || hex.EncodeToString(digest[:]) != want {
		t.Fatal("Xray reference digest mismatch")
	}
	root := t.TempDir()
	if external := os.Getenv("SPLICORE_PHASE34_PEER_LOGS"); external != "" {
		root = filepath.Join(external, strings.ReplaceAll(t.Name(), "/", "-"))
		if err = os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "config.json")
	if err = os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "peer.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-config", file)
	cmd.Stdout, cmd.Stderr = log, log
	var releasedAt time.Time
	if handoff != nil {
		handoff()
		releasedAt = time.Now()
	}
	if err = cmd.Start(); err != nil {
		_ = log.Close()
		return 0, logPath, err
	}
	until := time.Now().Add(4 * time.Second)
	t.Logf("xray_peer_start pid=%d address=%s handoff=%t release_at=%s started_at=%s",
		cmd.Process.Pid, address, handoff != nil, releasedAt.UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano))
	done := make(chan struct{})
	var exit error
	go func() {
		exit = cmd.Wait()
		close(done)
	}()
	ready := false
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
		_ = log.Close()
		t.Logf("xray_peer_exit pid=%d status=%v at=%s",
			cmd.Process.Pid, exit, time.Now().UTC().Format(time.RFC3339Nano))
		if ready {
			checkXrayPeerReleased(t, address, networks)
		}
	})
	exited := func() error {
		if exit == nil {
			return fmt.Errorf("external Xray exited before fixture readiness at %s; see peer.log", address)
		}
		return fmt.Errorf("external Xray rejected WireGuard fixture at %s; see peer.log: %w", address, exit)
	}
	for time.Now().Before(until) {
		select {
		case <-done:
			return cmd.Process.Pid, logPath, exited()
		default:
		}
		b, _ := os.ReadFile(logPath)
		if bytes.Contains(b, []byte("[Warning] core: Xray")) {
			ctx, cancel := context.WithDeadline(context.Background(), until)
			err := testkit.VerifyPeerProcessSockets(t, ctx, cmd.Process.Pid, address, networks...)
			cancel()
			if err != nil {
				return cmd.Process.Pid, logPath, err
			}
			select {
			case <-done:
				return cmd.Process.Pid, logPath, exited()
			default:
			}
			ready = true
			return cmd.Process.Pid, logPath, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cmd.Process.Pid, logPath, fmt.Errorf("external Xray startup timeout at %s", address)
}

func checkXrayPeerReleased(t *testing.T, address string, networks []string) {
	t.Helper()
	for _, network := range networks {
		var socket io.Closer
		var err error
		if network == "tcp" {
			socket, err = net.Listen("tcp4", address)
		} else {
			socket, err = net.ListenPacket("udp4", address)
		}
		if err != nil {
			t.Errorf("Xray %s listener release at %s: %v", network, address, err)
			continue
		}
		_ = socket.Close()
		t.Logf("xray_peer_rebind network=%s address=%s at=%s", network, address, time.Now().UTC().Format(time.RFC3339Nano))
	}
}

func xrayHostEcho(t *testing.T, ip string) {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(ip, "30034"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); <-done })
	p, err := net.ListenPacket("udp", net.JoinHostPort(ip, "30035"))
	if err != nil {
		t.Fatal(err)
	}
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		b := make([]byte, 65535)
		for {
			n, a, err := p.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = p.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { _ = p.Close(); <-udpDone })
}

func TestXrayWireGuardInterop(t *testing.T) {
	if os.Getenv("SPLICORE_PHASE34_XRAY_REFERENCE") == "" {
		t.Skip("external Xray WireGuard oracle not configured")
	}
	for _, pskEnabled := range []bool{false, true} {
		name := "no-psk"
		if pskEnabled {
			name = "psk"
		}
		t.Run(name, func(t *testing.T) {
			private, public := testKeys(t)
			remote, remotePublic := testKeys(t)
			var secret E.Secret
			psk := ""
			if pskEnabled {
				secret, _ = testKeys(t)
				psk = E.EncodeKey(secret.Reveal())
			}
			t.Run("Splicore-outbound-Xray-inbound", func(t *testing.T) {
				for _, ip := range testkit.RoutedHosts(t) {
					xrayHostEcho(t, ip)
				}
				lease := testkit.ReserveDualPeerPort(t, "127.0.0.1")
				xrayPeer(t, lease, xrayWireGuardServerConfig(t, lease.Port, E.EncodeKey(remote.Reveal()), public, psk), "udp")
				config := E.WireGuard{Tag: "xray-server", PrivateKey: private, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: remotePublic, PreSharedKey: secret, Endpoint: lease.Address(), AllowedIPs: []string{"0.0.0.0/0", "::/0"}}}}
				e, err := New(context.Background(), config, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = e.Close() })
				if err = e.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				for _, ip := range testkit.RoutedHosts(t) {
					xrayTCP(t, e, ip)
					oracleUDP(t, e, ip)
				}
			})
			t.Run("Xray-outbound-Splicore-inbound", func(t *testing.T) {
				config := E.WireGuard{Tag: "xray-client", PrivateKey: private, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: remotePublic, PreSharedKey: secret, AllowedIPs: []string{"10.34.0.2/32", "fd34::2/128"}}}}
				e, err := New(context.Background(), config, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = e.Close() })
				if err = e.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				lease := testkit.ReserveDualPeerPort(t, "127.0.0.1")
				var relays []string
				t.Cleanup(func() {
					// The child cleanup is registered after this callback, so it
					// joins Xray before checking its per-association sockets.
					for _, relay := range relays {
						checkXrayPeerReleased(t, relay, []string{"udp"})
					}
				})
				pid := xrayPeer(t, lease, map[string]any{
					"log": map[string]any{"loglevel": "warning"},
					"inbounds": []any{map[string]any{
						"listen": lease.Host, "port": lease.Port, "protocol": "socks",
						"settings": map[string]any{"auth": "noauth", "udp": true},
					}},
					"outbounds": []any{map[string]any{
						"protocol": "wireguard",
						"settings": map[string]any{
							"secretKey": E.EncodeKey(remote.Reveal()), "address": []string{"10.34.0.2", "fd34::2"}, "noKernelTun": true,
							"peers": []any{map[string]any{
								"publicKey": public, "preSharedKey": psk, "endpoint": net.JoinHostPort("127.0.0.1", itoa(e.Status().ListenPort)),
								"allowedIPs": []string{"0.0.0.0/0", "::/0"},
							}},
						},
					}},
				}, "tcp")
				for _, ip := range []string{"10.34.0.1", "fd34::1"} {
					c, err := net.DialTimeout("tcp", lease.Address(), 3*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					_ = c.SetDeadline(time.Now().Add(4 * time.Second))
					if _, err = socks.Handshake(c, socks.Connect, access.Endpoint{Host: ip, Port: 12345}); err != nil {
						_ = c.Close()
						t.Fatal(err)
					}
					payload := []byte("Xray to native WireGuard")
					if _, err = c.Write(payload); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(payload))
					if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(payload, got) {
						t.Fatalf("Xray client TCP %s: %v", ip, err)
					}
					_ = c.Close()
					control, err := net.DialTimeout("tcp", lease.Address(), 3*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					deadline := time.Now().Add(4 * time.Second)
					_ = control.SetDeadline(deadline)
					relay, err := socks.Handshake(control, socks.UDPAssociate, access.Endpoint{Host: "0.0.0.0", Port: 0})
					if err != nil {
						_ = control.Close()
						t.Fatal(err)
					}
					// Xray opens a separate OS-selected UDP relay for each
					// association, after its TCP listener is ready.
					relayAddress := net.JoinHostPort(relay.Host, itoa(int(relay.Port)))
					ctx, cancel := context.WithDeadline(context.Background(), deadline)
					err = testkit.VerifyPeerProcessSockets(t, ctx, pid, relayAddress, "udp")
					cancel()
					if err != nil {
						_ = control.Close()
						t.Fatal(err)
					}
					relays = append(relays, relayAddress)
					udp, err := net.Dial("udp", relayAddress)
					if err != nil {
						_ = control.Close()
						t.Fatal(err)
					}
					packet := testfixture.SOCKSPacket(udp, control)
					_ = packet.SetDeadline(time.Now().Add(4 * time.Second))
					dest := testfixture.Endpoint(net.JoinHostPort(ip, "12346"))
					if _, err = packet.WriteTo(payload, netaddr.UDP(dest)); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 512)
					n, _, err := packet.ReadFrom(buf)
					if err != nil || !bytes.Equal(payload, buf[:n]) {
						t.Fatalf("Xray client UDP: %v", err)
					}
					_ = packet.Close()

				}
			})
		})
	}
}

func xrayWireGuardServerConfig(t *testing.T, port int, secretKey, publicKey, psk string) map[string]any {
	t.Helper()
	return map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "wireguard",
			"settings": map[string]any{
				"secretKey": secretKey, "address": []string{"10.34.0.2", "fd34::2"}, "noKernelTun": true,
				"peers": []any{map[string]any{"publicKey": publicKey, "preSharedKey": psk, "allowedIPs": []string{"10.34.0.1/32", "fd34::1/128"}}},
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": xrayAllowedHosts(t)}}},
		}},
	}
}

// Xray's inbound proxy path is qualified for full-duplex payload exchange here;
// official wireguard-go interop separately qualifies TCP half-close semantics.
func xrayTCP(t *testing.T, e *Endpoint, ip string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := e.DialContext(ctx, access.Endpoint{Host: ip, Port: 30034})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	payload := bytes.Repeat([]byte("xray WireGuard"), 300)
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(payload, got) {
		t.Fatalf("Xray TCP payload: %v", err)
	}
}

func xrayAllowedHosts(t *testing.T) []string {
	t.Helper()
	var allowed []string
	for _, ip := range testkit.RoutedHosts(t) {
		suffix := "/128"
		if net.ParseIP(ip).To4() != nil {
			suffix = "/32"
		}
		allowed = append(allowed, ip+suffix)
	}
	return allowed
}
