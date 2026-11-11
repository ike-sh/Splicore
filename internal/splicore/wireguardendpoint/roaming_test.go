//go:build with_gvisor

package wireguardendpoint

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

// All relay readers retain the exact socket they own. Roaming switches between
// two concurrently owned back sockets, with no historical-port rebind premise.
type packetRelay struct {
	front               *net.UDPConn
	backs               [2]*net.UDPConn
	destination         *net.UDPAddr
	mu                  sync.Mutex
	client              *net.UDPAddr
	active              int
	last                []byte
	tamper              bool
	packets, keepalives int
	wg                  sync.WaitGroup
}

func newRelay(t *testing.T, port int) *packetRelay {
	t.Helper()
	r := &packetRelay{destination: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}}
	socket := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	r.front = socket()
	for i := range r.backs {
		r.backs[i] = socket()
	}
	t.Cleanup(func() {
		_ = r.front.Close()
		for _, c := range r.backs {
			_ = c.Close()
		}
		r.wg.Wait()
	})
	r.wg.Go(func() {
		b := make([]byte, 65535)
		for {
			n, source, err := r.front.ReadFromUDP(b)
			if err != nil {
				return
			}
			packet := append([]byte(nil), b[:n]...)
			r.mu.Lock()
			r.client = source
			r.packets++
			if n == 32 && binary.LittleEndian.Uint32(packet) == 4 {
				r.keepalives++
			}
			if n > 32 && binary.LittleEndian.Uint32(packet) == 4 {
				r.last = append([]byte(nil), packet...)
				if r.tamper {
					packet[len(packet)-1] ^= 1
				}
			}
			back := r.backs[r.active]
			r.mu.Unlock()
			_, _ = back.WriteToUDP(packet, r.destination)
		}
	})
	for _, back := range r.backs {
		r.wg.Add(1)
		go func(c *net.UDPConn) {
			defer r.wg.Done()
			b := make([]byte, 65535)
			for {
				n, _, err := c.ReadFromUDP(b)
				if err != nil {
					return
				}
				r.mu.Lock()
				client := r.client
				r.mu.Unlock()
				if client != nil {
					_, _ = r.front.WriteToUDP(b[:n], client)
				}
			}
		}(back)
	}
	return r
}

func TestWireGuardRoamingTamperReplayAndMalformed(t *testing.T) {
	ka, pa := testKeys(t)
	kb, pb := testKeys(t)
	d := &echoDispatcher{}
	bc := E.WireGuard{Tag: "b", PrivateKey: kb, Addresses: []string{"10.34.0.2/32"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.34.0.1/32"}}}}
	b, err := New(context.Background(), bc, Options{Dispatcher: d, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err = b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := newRelay(t, b.Status().ListenPort)
	ac := E.WireGuard{Tag: "a", PrivateKey: ka, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: pb, Endpoint: r.front.LocalAddr().String(), AllowedIPs: []string{"10.34.0.2/32"}}}}
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

func TestWireGuardKeepaliveLifecycle(t *testing.T) {
	for _, interval := range []int{0, 1} {
		t.Run(itoa(interval), func(t *testing.T) {
			private, _ := testKeys(t)
			_, public := testKeys(t)
			r := newRelay(t, 9)
			config := E.WireGuard{Tag: "keepalive", PrivateKey: private, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: public, Endpoint: r.front.LocalAddr().String(), AllowedIPs: []string{"10.34.0.2/32"}, PersistentKeepaliveInterval: interval}}}
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
