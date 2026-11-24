package native

import (
	"net"
	"sync"
	"testing"
)

// A peer's UDP context can outlive the client's socket. Keep each association's
// source endpoint reserved across the IPv4/IPv6 subtests: reusing a closed source
// port does not create an independent context at that still-running peer.
// Packet Close behavior is tested separately; this fixture owns the entire
// peer lifetime and requires every endpoint to be released at retirement.
type snellV5PeerPackets struct {
	t       *testing.T
	mu      sync.Mutex
	packets []net.PacketConn
	closed  bool
	once    sync.Once
}

func newSnellV5PeerPackets(t *testing.T) *snellV5PeerPackets {
	t.Helper()
	f := &snellV5PeerPackets{t: t}
	t.Cleanup(f.close)
	return f
}

func (f *snellV5PeerPackets) keep(p net.PacketConn) {
	f.mu.Lock()
	if !f.closed {
		f.packets = append(f.packets, p)
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()
	if err := p.Close(); err != nil {
		f.t.Error("late peer packet cleanup", err)
	}
}

func (f *snellV5PeerPackets) snapshot() []net.PacketConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]net.PacketConn(nil), f.packets...)
}

func (f *snellV5PeerPackets) close() {
	f.once.Do(func() {
		f.mu.Lock()
		f.closed = true
		packets := append([]net.PacketConn(nil), f.packets...)
		f.mu.Unlock()
		for _, p := range packets {
			if err := p.Close(); err != nil {
				f.t.Error("peer packet cleanup", err)
			}
		}
	})
}

func (f *snellV5PeerPackets) udpAddresses() []*net.UDPAddr {
	var addresses []*net.UDPAddr
	for _, p := range f.snapshot() {
		switch packet := p.(type) {
		case *snellV5Packet:
			packet.mu.Lock()
			child := packet.child
			packet.mu.Unlock()
			if raw, ok := child.(*snellRawPacket); ok {
				addresses = append(addresses, raw.LocalAddr().(*net.UDPAddr))
			}
		case *net.UDPConn:
			addresses = append(addresses, packet.LocalAddr().(*net.UDPAddr))
		}
	}
	return addresses
}

type snellV5PeerEndpoint struct {
	network string
	address string
}

func (f *snellV5PeerPackets) assertHeld(t *testing.T, want int) []snellV5PeerEndpoint {
	t.Helper()
	seen := map[string]bool{}
	var endpoints []snellV5PeerEndpoint
	for _, a := range f.udpAddresses() {
		if a.Port == 0 || seen[a.String()] {
			t.Fatal("independent associations reused a source endpoint", a)
		}
		seen[a.String()] = true
		network := "udp6"
		if a.IP.To4() != nil {
			network = "udp4"
		}
		endpoints = append(endpoints, snellV5PeerEndpoint{network: network, address: a.String()})
	}
	if len(endpoints) != want {
		t.Fatalf("independent UDP endpoints: got %d, want %d", len(endpoints), want)
	}
	for _, p := range f.snapshot() {
		if packet, ok := p.(*snellV5Packet); ok {
			packet.mu.Lock()
			closed := packet.closed
			packet.mu.Unlock()
			if closed {
				t.Fatal("association closed before peer fixture retirement")
			}
		}
	}
	t.Logf("independent UDP association endpoints retained: %d", len(endpoints))
	return endpoints
}

func (f *snellV5PeerPackets) assertClosed(t *testing.T) {
	t.Helper()
	for _, p := range f.snapshot() {
		if packet, ok := p.(*snellV5Packet); ok {
			packet.mu.Lock()
			closed := packet.closed
			packet.mu.Unlock()
			if !closed {
				t.Fatal("association remained open after dialer retirement")
			}
		}
	}
}

func (f *snellV5PeerPackets) assertReleased(t *testing.T, endpoints []snellV5PeerEndpoint, want int) {
	t.Helper()
	if len(endpoints) != want {
		t.Fatalf("retired UDP endpoints: got %d, want %d", len(endpoints), want)
	}
	for _, endpoint := range endpoints {
		p, err := net.ListenPacket(endpoint.network, endpoint.address)
		if err != nil {
			t.Fatal("retired association endpoint is not rebindable", endpoint, err)
		}
		if err = p.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("retired UDP association endpoints rebindable: %d", len(endpoints))
}

func TestSnellV5PacketFixtureRetainsIndependentEndpoints(t *testing.T) {
	f := newSnellV5PeerPackets(t)
	for range 12 {
		p, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		f.keep(p)
	}
	held := f.assertHeld(t, 12)
	for _, endpoint := range held {
		duplicate, err := net.ListenPacket(endpoint.network, endpoint.address)
		if err == nil {
			_ = duplicate.Close()
		}
		if !addressInUse(err) {
			t.Fatal("live fixture endpoint did not exclude duplicate bind", endpoint, err)
		}
	}
	f.close()
	f.close()
	f.assertReleased(t, held, 12)

	late, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	lateEndpoint := []snellV5PeerEndpoint{{network: "udp4", address: late.LocalAddr().String()}}
	f.keep(late)
	f.assertReleased(t, lateEndpoint, 1)
}
