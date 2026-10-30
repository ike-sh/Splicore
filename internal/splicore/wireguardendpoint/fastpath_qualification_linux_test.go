//go:build linux && with_gvisor

package wireguardendpoint

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

// Reuse the frozen Phase34 independent oracles and assertions with explicit
// kernel configuration. The original userspace qualification remains intact.
func TestPhase36OfficialWireGuardInterop(t *testing.T) {
	requireFastpath(t)
	for _, pskEnabled := range []bool{false, true} {
		name := "no-psk"
		if pskEnabled {
			name = "matching-psk"
		}
		t.Run(name, func(t *testing.T) {
			private, public := testKeys(t)
			psk := ""
			var secret E.Secret
			if pskEnabled {
				secret, _ = testKeys(t)
				psk = E.EncodeKey(secret.Reveal())
			}
			first := startOracle(t, public, []string{"10.34.0.2", "fd34::2"}, []string{"10.34.0.1/32", "fd34::1/128"}, psk, 1)
			second := startOracle(t, public, []string{"10.34.0.3", "fd34::3"}, []string{"10.34.0.1/32", "fd34::1/128"}, psk, 0)
			config := E.WireGuard{Backend: E.Kernel, Tag: "official", PrivateKey: private, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{
				{PublicKey: second.PublicKey, PreSharedKey: secret, Endpoint: net.JoinHostPort("127.0.0.1", itoa(second.ListenPort)), AllowedIPs: []string{"10.34.0.3/32", "fd34::3/128"}},
				{PublicKey: first.PublicKey, PreSharedKey: secret, Endpoint: net.JoinHostPort("127.0.0.1", itoa(first.ListenPort)), AllowedIPs: []string{"10.34.0.0/24", "fd34::/64"}, PersistentKeepaliveInterval: 1},
			}}
			dispatcher := &echoDispatcher{}
			e, err := New(context.Background(), config, Options{Dispatcher: dispatcher, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = e.Close() })
			if err = e.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			first.endpoint(t, e.Status().ListenPort)
			second.endpoint(t, e.Status().ListenPort)
			for _, ip := range []string{"10.34.0.2", "fd34::2", "10.34.0.3", "fd34::3"} {
				oracleTCP(t, e, ip)
				oracleUDP(t, e, ip)
			}
			for _, o := range []*oracle{first, second} {
				for _, ip := range []string{"10.34.0.1", "fd34::1"} {
					o.dial(t, "tcp", ip, false)
					o.dial(t, "udp", ip, false)
				}
			}
			status := e.Status()
			if status.Peers[0].LastHandshake.IsZero() || status.Peers[1].LastHandshake.IsZero() {
				t.Fatal("independent peer handshake missing")
			}
			dispatcher.mu.Lock()
			seen := map[string]bool{}
			for _, id := range dispatcher.identities {
				seen[id.PeerPublicKey] = true
			}
			dispatcher.mu.Unlock()
			if !seen[first.PublicKey] || !seen[second.PublicKey] {
				t.Fatal("multi-peer credential identity lost")
			}
			raw, _ := json.Marshal(status)
			if strings.Contains(string(raw), E.EncodeKey(private.Reveal())) || psk != "" && strings.Contains(string(raw), psk) {
				t.Fatal("status leaked secret")
			}
		})
	}
}

func TestPhase36OfficialDisallowedSource(t *testing.T) {
	requireFastpath(t)
	private, public := testKeys(t)
	o := startOracle(t, public, []string{"10.34.0.99"}, []string{"10.34.0.1/32"}, "", 0)
	config := E.WireGuard{Backend: E.Kernel, Tag: "source-negative", PrivateKey: private, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: o.PublicKey, AllowedIPs: []string{"10.34.0.2/32"}}}}
	d := &echoDispatcher{}
	e, err := New(context.Background(), config, Options{Dispatcher: d, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if err = e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	o.endpoint(t, e.Status().ListenPort)
	o.dial(t, "udp", "10.34.0.1", true)
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.identities) != 0 {
		t.Fatal("disallowed source reached Core dispatcher")
	}
	if e.Status().Peers[0].LastHandshake.IsZero() {
		t.Fatal("negative test did not authenticate the peer")
	}
}

// Ensure the fixture remains an external executable, rather than an alternate
// production stack linked into the Core process.

func TestPhase36KernelRoaming(t *testing.T) {
	requireFastpath(t)
	ka, pa := testKeys(t)
	kb, pb := testKeys(t)
	d := &echoDispatcher{}
	bc := E.WireGuard{Backend: E.Kernel, Tag: "b", PrivateKey: kb, Addresses: []string{"10.34.0.2/32"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.34.0.1/32"}}}}
	b, err := New(context.Background(), bc, Options{Dispatcher: d, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err = b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := newRelay(t, b.Status().ListenPort)
	ac := E.WireGuard{Backend: E.Kernel, Tag: "a", PrivateKey: ka, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: pb, Endpoint: r.front.LocalAddr().String(), AllowedIPs: []string{"10.34.0.2/32"}}}}
	a, err := New(context.Background(), ac, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err = a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	target := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.34.0.2:12346"))
	c, err := a.ListenPacket(context.Background(), access.Endpoint{Host: "10.34.0.2", Port: 12346})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	exchange := func() {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.WriteTo([]byte("positive control"), target); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		if n, _, err := c.ReadFrom(buf); err != nil || string(buf[:n]) != "positive control" {
			t.Fatalf("positive control: %v", err)
		}
	}
	rejected := func() {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, _, err := c.ReadFrom(make([]byte, 100)); err == nil {
			t.Fatal("tampered/replayed packet accepted")
		}
	}
	exchange()
	original := b.Status().Peers[0].CurrentEndpoint
	r.mu.Lock()
	r.active = 1
	r.mu.Unlock()
	exchange()
	roamed := b.Status().Peers[0].CurrentEndpoint
	if original == roamed || roamed != r.backs[1].LocalAddr().String() {
		t.Fatalf("authenticated roaming missing: %s -> %s", original, roamed)
	}
	r.mu.Lock()
	replay := append([]byte(nil), r.last...)
	r.mu.Unlock()
	if len(replay) <= 32 {
		t.Fatal("no captured transport packet")
	}
	if _, err = r.backs[1].WriteToUDP(replay, r.destination); err != nil {
		t.Fatal(err)
	}
	rejected()
	exchange()
	r.mu.Lock()
	r.tamper = true
	r.mu.Unlock()
	if _, err = c.WriteTo([]byte("tampered"), target); err != nil {
		t.Fatal(err)
	}
	rejected()
	r.mu.Lock()
	r.tamper = false
	r.mu.Unlock()
	exchange()
	for _, size := range []int{0, 1, 3, 4, 31, 32, 64, 92, 148, 149, 2048, 65507} {
		bad := make([]byte, size)
		if size >= 4 {
			binary.LittleEndian.PutUint32(bad, 1)
		}
		if _, err = r.backs[1].WriteToUDP(bad, r.destination); err != nil {
			t.Fatal(err)
		}
	}
	exchange()
	if b.Status().Peers[0].PublicKey != pa {
		t.Fatal("roaming changed credential identity")
	}
}

func TestPhase36KernelKeepalive(t *testing.T) {
	requireFastpath(t)
	for _, interval := range []int{0, 1} {
		t.Run(itoa(interval), func(t *testing.T) {
			private, _ := testKeys(t)
			_, public := testKeys(t)
			r := newRelay(t, 9)
			config := E.WireGuard{Backend: E.Kernel, Tag: "keepalive", PrivateKey: private, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: public, Endpoint: r.front.LocalAddr().String(), AllowedIPs: []string{"10.34.0.2/32"}, PersistentKeepaliveInterval: interval}}}
			e, err := New(context.Background(), config, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = e.Close() })
			if err = e.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			// With no user traffic, enabled upstream keepalive initiates a handshake;
			// disabled keepalive remains silent. An unavailable peer cannot authenticate.
			time.Sleep(80 * time.Millisecond)
			r.mu.Lock()
			count := r.packets
			r.mu.Unlock()
			if (interval == 0 && count != 0) || (interval == 1 && count == 0) {
				t.Fatalf("keepalive=%d packets=%d", interval, count)
			}
			closedStatus(t, e)
		})
	}
}

func TestPhase36KernelWrongCredentials(t *testing.T) {
	requireFastpath(t)
	for _, mode := range []string{"wrong-psk", "wrong-peer-key", "unauthorized-peer"} {
		t.Run(mode, func(t *testing.T) {
			ka, pa := testKeys(t)
			kb, pb := testKeys(t)
			_, wrong := testKeys(t)
			da, db := &echoDispatcher{}, &echoDispatcher{}
			ac := E.WireGuard{Backend: E.Kernel, Tag: "a", PrivateKey: ka, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: pb, AllowedIPs: []string{"10.34.0.2/32"}}}}
			bc := E.WireGuard{Backend: E.Kernel, Tag: "b", PrivateKey: kb, Addresses: []string{"10.34.0.2/32"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.34.0.1/32"}}}}
			switch mode {
			case "wrong-psk":
				ac.Peers[0].PreSharedKey, _ = testKeys(t)
				bc.Peers[0].PreSharedKey, _ = testKeys(t)
			case "wrong-peer-key":
				ac.Peers[0].PublicKey = wrong
			case "unauthorized-peer":
				bc.Peers[0].PublicKey = wrong
			}
			b, err := New(context.Background(), bc, Options{Dispatcher: db, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.Close() })
			if err = b.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			ac.Peers[0].Endpoint = net.JoinHostPort("127.0.0.1", itoa(b.Status().ListenPort))
			a, err := New(context.Background(), ac, Options{Dispatcher: da, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			if err = a.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			c, err := a.DialContext(ctx, access.Endpoint{Host: "10.34.0.2", Port: 12345})
			if c != nil {
				_ = c.Close()
			}
			if err == nil {
				t.Fatal("wrong credentials accepted")
			}
			db.mu.Lock()
			defer db.mu.Unlock()
			if len(db.identities) != 0 {
				t.Fatal("unauthenticated traffic reached Core")
			}
		})
	}
}

func TestPhase36LinuxKernelOracle(t *testing.T) {
	requireFastpath(t)
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
			config := E.WireGuard{Backend: E.Kernel, Tag: "kernel-oracle", PrivateKey: private, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: remotePublic, PreSharedKey: psk, Endpoint: "127.0.0.1:33436", AllowedIPs: []string{"10.34.0.2/32", "fd34::2/128"}}}}
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
				xrayHostEcho(t, ip)
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

func TestPhase36KernelPendingDNSClose(t *testing.T) {
	requireFastpath(t)
	for _, phase := range []string{"start", "tcp", "udp"} {
		t.Run(phase, func(t *testing.T) {
			private, _ := testKeys(t)
			_, public := testKeys(t)
			entered := make(chan struct{})
			finished := make(chan struct{})
			var once sync.Once
			lookup := func(ctx context.Context, _ string) ([]netip.Addr, error) {
				once.Do(func() { close(entered) })
				<-ctx.Done()
				close(finished)
				return nil, ctx.Err()
			}
			config := E.WireGuard{Backend: E.Kernel, Tag: "dns", PrivateKey: private, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: public, AllowedIPs: []string{"10.34.0.2/32"}}}}
			if phase == "start" {
				config.Peers[0].Endpoint = "peer.invalid:51820"
			}
			e, err := New(context.Background(), config, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New(), LookupHost: lookup, LookupEndpoint: lookup})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = e.Close() })
			if phase != "start" {
				if err = e.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				var err error
				switch phase {
				case "start":
					err = e.Start(context.Background())
				case "tcp":
					_, err = e.DialContext(context.Background(), access.Endpoint{Host: "target.invalid", Port: 443})
				case "udp":
					_, err = e.ListenPacket(context.Background(), access.Endpoint{Host: "target.invalid", Port: 53})
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("DNS not entered")
			}
			closedStatus(t, e)
			select {
			case <-finished:
			default:
				t.Fatal("Close did not join DNS")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled operation succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("pending operation leaked")
			}
		})
	}
}
