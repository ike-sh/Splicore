//go:build with_gvisor

package wireguardendpoint

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestWireGuardMultiPeerChurn100(t *testing.T) {
	ka, pa := testKeys(t)
	kb, pb := testKeys(t)
	kc, pc := testKeys(t)
	baseFD, baseG := fdCount(), runtime.NumGoroutine()
	for cycle := range 100 {
		build := func(config E.WireGuard) *Endpoint {
			t.Helper()
			e, err := New(context.Background(), config, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			if err = e.Start(context.Background()); err != nil {
				_ = e.Close()
				t.Fatal(err)
			}
			return e
		}
		b := build(E.WireGuard{Tag: "b", PrivateKey: kb, Addresses: []string{"10.34.0.2/32", "fd34::2/128"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.34.0.1/32", "fd34::1/128"}}}})
		c := build(E.WireGuard{Tag: "c", PrivateKey: kc, Addresses: []string{"10.34.0.3/32", "fd34::3/128"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.34.0.1/32", "fd34::1/128"}}}})
		peers := []E.WireGuardPeer{{PublicKey: pb, Endpoint: net.JoinHostPort("127.0.0.1", itoa(b.Status().ListenPort)), AllowedIPs: []string{"10.34.0.0/24", "fd34::/64"}}, {PublicKey: pc, Endpoint: net.JoinHostPort("127.0.0.1", itoa(c.Status().ListenPort)), AllowedIPs: []string{"10.34.0.3/32", "fd34::3/128"}}}
		if cycle%2 == 1 {
			peers[0], peers[1] = peers[1], peers[0]
		}
		a := build(E.WireGuard{Tag: "a", PrivateKey: ka, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: peers})
		for _, entry := range []struct{ ip, key string }{{"10.34.0.2", pb}, {"fd34::2", pb}, {"10.34.0.3", pc}, {"fd34::3", pc}} {
			if key, ok := a.peerFor(netip.MustParseAddr(entry.ip)); !ok || key != entry.key {
				t.Fatal("declaration order changed LPM peer selection")
			}
			transferUDP(t, a, entry.ip, 64)
		}
		if cycle%10 == 0 {
			transferTCP(t, a, "10.34.0.2")
			transferTCP(t, a, "fd34::3")
		}
		status := a.Status()
		for _, p := range status.Peers {
			if p.LastHandshake.IsZero() || p.RXBytes == 0 {
				t.Fatal("independent peer did not handshake")
			}
		}
		closedStatus(t, a)
		closedStatus(t, b)
		closedStatus(t, c)
		if (cycle+1)%25 == 0 {
			runtime.GC()
			t.Logf("multi-peer cycle=%d goroutines=%d fds=%d devices=0 sockets=0 queues=0", cycle+1, runtime.NumGoroutine(), fdCount())
		}
	}
	runtime.GC()
	if final := fdCount(); baseFD >= 0 && final > baseFD+2 {
		t.Fatalf("multi-peer fd growth %d -> %d", baseFD, final)
	}
	if final := runtime.NumGoroutine(); final > baseG+12 {
		t.Fatalf("multi-peer goroutine growth %d -> %d", baseG, final)
	}
}
