//go:build linux && with_gvisor

package amneziawgendpoint

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

// This supplementary oracle runs only inside a disposable validation network
// namespace. Production never invokes ip/wg or requires a kernel interface.
func TestAWGStandardWGKernelCompatibility(t *testing.T) {
	wg := os.Getenv("SPLICORE_PHASE34_KERNEL_WG")
	if wg == "" {
		t.Skip("supplementary kernel oracle requires external wg and isolated CAP_NET_ADMIN namespace")
	}
	command := func(binary string, args ...string) {
		t.Helper()
		out, err := exec.Command(binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("kernel fixture command %s failed: %v %s", binary, err, out)
		}
	}
	for _, pskEnabled := range []bool{false, true} {
		name := "no-psk"
		if pskEnabled {
			name = "psk"
		}
		t.Run(name, func(t *testing.T) {
			command("ip", "link", "add", "phase34wg", "type", "wireguard")
			t.Cleanup(func() { command("ip", "link", "del", "phase34wg") })
			private, public := testKeys(t)
			remote, remotePublic := testKeys(t)
			var psk E.Secret
			if pskEnabled {
				psk, _ = testKeys(t)
			}
			config := E.AmneziaWG{Protocol: "amneziawg", Version: "3.1", Tag: "kernel-oracle", PrivateKey: private, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: remotePublic, PreSharedKey: psk, Endpoint: "127.0.0.1:33436", AllowedIPs: []string{"10.34.0.2/32", "fd34::2/128"}}}}
			e, err := New(context.Background(), config, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closedStatus(t, e) })
			if err = e.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			file := filepath.Join(root, "private-key")
			if err = os.WriteFile(file, []byte(E.EncodeKey(remote.Reveal())), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"set", "phase34wg", "private-key", file, "listen-port", "33436", "peer", public, "allowed-ips", "10.34.0.1/32,fd34::1/128", "endpoint", net.JoinHostPort("127.0.0.1", itoa(e.Status().ListenPort))}
			if pskEnabled {
				pskFile := filepath.Join(root, "preshared-key")
				if err = os.WriteFile(pskFile, []byte(E.EncodeKey(psk.Reveal())), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "preshared-key", pskFile)
			}
			command(wg, args...)
			command("ip", "addr", "add", "10.34.0.2/24", "dev", "phase34wg")
			command("ip", "-6", "addr", "add", "fd34::2/64", "dev", "phase34wg", "nodad")
			command("ip", "link", "set", "dev", "phase34wg", "mtu", "1420", "up")
			for _, ip := range []string{"10.34.0.2", "fd34::2"} {
				compatHostEcho(t, ip)
				oracleTCP(t, e, ip)
				oracleUDP(t, e, ip)
			}
			for _, ip := range []string{"10.34.0.1", "fd34::1"} {
				for _, network := range []string{"tcp", "udp"} {
					c, err := net.DialTimeout(network, net.JoinHostPort(ip, "12345"), 3*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					payload := bytes.Repeat([]byte("kernel-WireGuard"), 30)
					if _, err = c.Write(payload); err != nil {
						_ = c.Close()
						t.Fatal(err)
					}
					got := make([]byte, len(payload))
					if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
						_ = c.Close()
						t.Fatalf("kernel inbound %s %s: %v", network, ip, err)
					}
					_ = c.Close()
				}
			}
			if e.Status().Peers[0].LastHandshake.IsZero() {
				t.Fatal("kernel handshake not observed")
			}
		})
	}
}

func compatHostEcho(t *testing.T, ip string) {
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
