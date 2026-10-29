//go:build with_gvisor

package wireguardendpoint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func xrayPeer(t *testing.T, config map[string]any) {
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
	if hex.EncodeToString(digest[:]) != "a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e" {
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
	if err = cmd.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done; _ = log.Close() })
	until := time.Now().Add(4 * time.Second)
	for time.Now().Before(until) {
		b, _ := os.ReadFile(logPath)
		if bytes.Contains(b, []byte("[Warning] core: Xray")) {
			return
		}
		select {
		case err := <-done:
			done <- err
			t.Fatal("external Xray rejected WireGuard fixture; see peer.log", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("external Xray startup timeout")
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
				for _, ip := range []string{"192.0.2.29", "2001:db8::29"} {
					xrayHostEcho(t, ip)
				}
				xrayPeer(t, map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 33434, "protocol": "wireguard", "settings": map[string]any{"secretKey": E.EncodeKey(remote.Reveal()), "address": []string{"10.34.0.2", "fd34::2"}, "noKernelTun": true, "peers": []any{map[string]any{"publicKey": public, "preSharedKey": psk, "allowedIPs": []string{"10.34.0.1/32", "fd34::1/128"}}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"192.0.2.29/32", "2001:db8::29/128"}}}}}}})
				config := E.WireGuard{Tag: "xray-server", PrivateKey: private, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: remotePublic, PreSharedKey: secret, Endpoint: "127.0.0.1:33434", AllowedIPs: []string{"0.0.0.0/0", "::/0"}}}}
				e, err := New(context.Background(), config, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = e.Close() })
				if err = e.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				for _, ip := range []string{"192.0.2.29", "2001:db8::29"} {
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
				xrayPeer(t, map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 33435, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"protocol": "wireguard", "settings": map[string]any{"secretKey": E.EncodeKey(remote.Reveal()), "address": []string{"10.34.0.2", "fd34::2"}, "noKernelTun": true, "peers": []any{map[string]any{"publicKey": public, "preSharedKey": psk, "endpoint": net.JoinHostPort("127.0.0.1", itoa(e.Status().ListenPort)), "allowedIPs": []string{"0.0.0.0/0", "::/0"}}}}}}})
				for _, ip := range []string{"10.34.0.1", "fd34::1"} {
					c, err := net.DialTimeout("tcp", "127.0.0.1:33435", 3*time.Second)
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
					control, err := net.DialTimeout("tcp", "127.0.0.1:33435", 3*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					_ = control.SetDeadline(time.Now().Add(4 * time.Second))
					relay, err := socks.Handshake(control, socks.UDPAssociate, access.Endpoint{Host: "0.0.0.0", Port: 0})
					if err != nil {
						_ = control.Close()
						t.Fatal(err)
					}
					udp, err := net.Dial("udp", net.JoinHostPort(relay.Host, itoa(int(relay.Port))))
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
