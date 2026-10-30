//go:build linux && with_gvisor

package clientruntime

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/amneziawgendpoint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/nativetun"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestPhase37NativeTUNToAWGUserspace(t *testing.T) {
	ctx := context.Background()
	keys := func() (E.Secret, string) {
		private, public, err := amneziawgendpoint.GenerateKeys()
		if err != nil {
			t.Fatal(err)
		}
		secret, err := E.ParseSecret(private)
		if err != nil {
			t.Fatal(err)
		}
		return secret, public
	}
	ka, pa := keys()
	kb, pb := keys()
	makeEndpoint := func(c E.AmneziaWG) *amneziawgendpoint.Endpoint {
		c.S1, c.S2, c.S3, c.S4 = 12, 13, 14, 15
		c.HeaderProtectionKey, _ = E.ParseSecret(E.EncodeKey([32]byte{37, 31}))
		c.ContentPaddingAddition = E.AWGRange{Min: 5, Max: 9}
		e, err := amneziawgendpoint.New(ctx, c, amneziawgendpoint.Options{Dispatcher: kernelTUNEcho{}, Underlay: underlay.New()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := e.Close(); err != nil {
				t.Error(err)
			}
		})
		if err = e.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return e
	}
	server := makeEndpoint(E.AmneziaWG{Protocol: "amneziawg", Version: "3.1", Backend: E.AWGUserspace, Tag: "tun-peer", PrivateKey: kb, Addresses: []string{"10.36.0.2/32", "fd36::2/128"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.36.0.1/32", "fd36::1/128"}}}})
	endpoint := makeEndpoint(E.AmneziaWG{Protocol: "amneziawg", Version: "3.1", Backend: E.AWGUserspace, Tag: "tun-core", PrivateKey: ka, Addresses: []string{"10.36.0.1/32", "fd36::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: pb, Endpoint: net.JoinHostPort("127.0.0.1", strconv.Itoa(server.Status().ListenPort)), AllowedIPs: []string{"10.36.0.2/32", "fd36::2/128"}}}})
	m := New()
	defer m.Close(ctx)
	inID, _ := identity.NewID()
	outID, _ := identity.NewID()
	lease := &dialerLease{dialer: BorrowedEndpoint{Lookup: func() (ports.ClientDialer, error) { return endpoint, nil }}}
	lease.refs.Store(1)
	gen := &snapshot{state: client.ProfileState{Enabled: true}, outbounds: map[identity.ID]ports.ClientDialer{outID: lease}, routes: map[identity.ID]identity.ID{inID: outID}, inCounters: map[identity.ID]*counter{inID: {}}, outCounters: map[identity.ID]*counter{outID: {}}}
	gen.state.Route.DefaultOutbound = outID
	gen.refs.Store(1)
	var err error
	gen.network, err = networkruntime.New(P.Config{}, gen.outbounds, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gen.release()
	a, b := make(chan []byte, 256), make(chan []byte, 256)
	coreDevice := &kernelTUNDevice{receive: a, send: b, done: make(chan struct{})}
	appDevice := &kernelTUNDevice{receive: b, send: a, done: make(chan struct{})}
	ingress := newTUNIngress(m, client.LocalInbound{ID: inID, Kind: "tun", TUN: &client.TUNSettings{MTU: 1500, Addresses: []string{"198.18.0.1/30", "fd18::1/126"}}}, gen)
	if err = ingress.start(coreDevice); err != nil {
		t.Fatal(err)
	}
	defer ingress.stop()
	front, err := nativetun.New(ctx, appDevice, nativetun.Options{MTU: 1500, Addresses: []netip.Addr{netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("fd18::2")}, Dispatcher: kernelTUNEcho{}})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	if err = front.Start(); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"198.18.0.2", "10.36.0.2"}, {"fd18::2", "fd36::2"}} {
		local, remote := netip.MustParseAddr(pair[0]), netip.MustParseAddrPort(net.JoinHostPort(pair[1], "12345"))
		c, err := front.DialTCP(ctx, local, remote)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte("native TUN to Core AWG outbound")
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err = io.ReadFull(c, got); err != nil || string(got) != string(payload) {
			t.Fatalf("TUN kernel TCP: %v", err)
		}
		c.Close()
		p, err := front.ListenUDP(ctx, local)
		if err != nil {
			t.Fatal(err)
		}
		_ = p.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = p.WriteTo(payload, net.UDPAddrFromAddrPort(remote)); err != nil {
			t.Fatal(err)
		}
		n, _, err := p.ReadFrom(got)
		if err != nil || string(got[:n]) != string(payload) {
			t.Fatalf("TUN kernel UDP: %v", err)
		}
		p.Close()
	}
	if endpoint.Status().Selected != E.AWGUserspace {
		t.Fatal("TUN selected a userspace WG engine")
	}
	t.Log("native TUN/gVisor -> Core routing/session relay -> borrowed AWG userspace outbound: TCP/UDP IPv4/IPv6 PASS")
}
