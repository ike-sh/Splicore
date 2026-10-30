//go:build linux && with_gvisor

package clientruntime

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/nativetun"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/internal/splicore/wireguardendpoint"
)

type kernelTUNDevice struct {
	receive, send chan []byte
	done          chan struct{}
	once          sync.Once
}

func (*kernelTUNDevice) Start() error       { return nil }
func (d *kernelTUNDevice) Interrupt() error { d.once.Do(func() { close(d.done) }); return nil }
func (d *kernelTUNDevice) Close() error     { return d.Interrupt() }
func (d *kernelTUNDevice) Read(p []byte) (int, error) {
	select {
	case <-d.done:
		return 0, net.ErrClosed
	case packet := <-d.receive:
		return copy(p, packet), nil
	}
}

func (d *kernelTUNDevice) Write(p []byte) (int, error) {
	select {
	case <-d.done:
		return 0, net.ErrClosed
	case d.send <- append([]byte(nil), p...):
		return len(p), nil
	}
}

type kernelTUNEcho struct{}

func (kernelTUNEcho) TCP(_ context.Context, c net.Conn, _, _ netip.AddrPort) {
	_, _ = io.Copy(c, c)
}

func (kernelTUNEcho) UDP(_ context.Context, c net.Conn, _, _ netip.AddrPort) {
	p := make([]byte, 65535)
	for {
		n, err := c.Read(p)
		if err != nil {
			return
		}
		if _, err = c.Write(p[:n]); err != nil {
			return
		}
	}
}

func TestPhase36NativeTUNToKernelWireGuard(t *testing.T) {
	if os.Getenv("SPLICORE_PHASE36_KERNEL") != "1" {
		t.Skip("requires explicit privileged Linux kernel qualification")
	}
	ctx := context.Background()
	keys := func() (E.Secret, string) {
		private, public, err := wireguardendpoint.GenerateKeys()
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
	makeEndpoint := func(c E.WireGuard) *wireguardendpoint.Endpoint {
		e, err := wireguardendpoint.New(ctx, c, wireguardendpoint.Options{Dispatcher: kernelTUNEcho{}, Underlay: underlay.New()})
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
	server := makeEndpoint(E.WireGuard{Backend: E.Kernel, Tag: "tun-peer", PrivateKey: kb, Addresses: []string{"10.36.0.2/32", "fd36::2/128"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.36.0.1/32", "fd36::1/128"}}}})
	endpoint := makeEndpoint(E.WireGuard{Backend: E.Kernel, Tag: "tun-core", PrivateKey: ka, Addresses: []string{"10.36.0.1/32", "fd36::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: pb, Endpoint: net.JoinHostPort("127.0.0.1", strconv.Itoa(server.Status().ListenPort)), AllowedIPs: []string{"10.36.0.2/32", "fd36::2/128"}}}})
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
		payload := []byte("native TUN to Core kernel outbound")
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
	if endpoint.Status().Selected != E.Kernel {
		t.Fatal("TUN selected a userspace WG engine")
	}
	t.Log("native TUN/gVisor -> Core routing/session relay -> borrowed kernel WG outbound: TCP/UDP IPv4/IPv6 PASS")
}
