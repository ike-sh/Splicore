//go:build with_gvisor

package clientruntime

import (
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/miekg/dns"
)

// No connection is sent to these synthetic endpoint IPs. This test-only adapter
// exercises the real protected packet factory before an owned in-memory echo.
type integrationFactory struct {
	endpoints []string
	closed    chan string
	backend   *testkit.FakeWindowsNetworkBackend
}

func (*integrationFactory) Capability() ports.OutboundCapability {
	return ports.OutboundCapability{Protocol: "snell", Engine: "native", TCP: true}
}
func (*integrationFactory) Validate(client.RemoteNode, access.Credential) error { return nil }
func (f *integrationFactory) Build(ctx context.Context, n client.RemoteNode, _ access.Credential) (ports.ClientDialer, error) {
	if !f.backend.Has(n.Endpoint.Host) {
		return nil, identity.Err(identity.Unavailable, "publication preceded infrastructure protection")
	}
	d, e := underlay.DialerFrom(ctx, underlay.ProxyUnderlay)
	if e != nil {
		return nil, e
	}
	f.endpoints = append(f.endpoints, n.Endpoint.Host)
	return &integrationDialer{d: d, endpoint: n.Endpoint, closed: f.closed}, nil
}

type integrationDialer struct {
	d        *underlay.Dialer
	endpoint access.Endpoint
	closed   chan string
}

func (d *integrationDialer) DialContext(ctx context.Context, _ access.Endpoint) (net.Conn, error) {
	p, e := d.d.ListenPacket(ctx, "udp4", "127.0.0.1:0", underlay.EndpointAddress(d.endpoint.Host, d.endpoint.Port))
	if e != nil {
		return nil, e
	}
	_ = p.Close()
	a, b := net.Pipe()
	go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
	return a, nil
}
func (d *integrationDialer) Close() error { d.closed <- d.endpoint.Host; return nil }
func runtimeID() identity.ID              { v, _ := identity.NewID(); return v }

func TestUnderlayDynamicDNSReusedTUNAndRuntimeRetirement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	x := testkit.NewUnderlay(t)
	m := NewWithUnderlay(x.Factory)
	// Owned simulated TUN ingress goes through production prepareHost's reuse
	// branch, with a separate journal generation from infrastructure routes.
	tunLease, e := x.Host.Prepare(ctx, []hostnetwork.Record{{Kind: "interface", Interface: "fixtureTun", Addresses: []string{"198.18.0.1/30"}, MTU: 1500}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	caps := hostnetwork.Capabilities{TUN: "experimental", Stack: "gvisor", AutoRoute: "implemented"}
	m.host = &hostController{manager: x.Host, platform: hostnetwork.NewPlatform(), capabilities: &caps}
	defer func() {
		if e := m.Close(ctx); e != nil {
			t.Error(e)
		}
	}()
	var answer atomic.Pointer[string]
	initial := "192.0.2.1"
	answer.Store(&initial)
	packet, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ready := make(chan struct{})
	dnsDone := make(chan error, 1)
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		if value := answer.Load(); value != nil && q.Question[0].Qtype == dns.TypeA {
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(*value)}}
		}
		_ = w.WriteMsg(r)
	})}
	go func() { dnsDone <- server.ActivateAndServe() }()
	<-ready
	defer func() {
		server.Shutdown()
		if e := <-dnsDone; e != nil {
			t.Error(e)
		}
	}()
	reservation, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := uint16(reservation.Addr().(*net.TCPAddr).Port)
	reservation.Close()
	nid, cid, oid, lid, dnsID, tunID := runtimeID(), runtimeID(), runtimeID(), runtimeID(), runtimeID(), runtimeID()
	state := client.Empty()
	state.Nodes = []client.RemoteNode{{ID: nid, Name: "fixture", Protocol: access.ProtocolKey{Protocol: "snell", WireVersion: "6", FeatureProfile: "base"}, Endpoint: access.Endpoint{Host: "node.fixture.invalid", Port: 443}, CredentialID: cid, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: []byte(`{"version":6}`)}}}
	state.Outbounds = append(state.Outbounds, client.Outbound{ID: oid, Name: "fixture", Kind: "proxy", NodeID: &nid, Engine: "native"})
	state.Route.DefaultOutbound = oid
	spec := client.LocalInbound{ID: tunID, Name: "tun-fixture", Kind: "tun", TUN: &client.TUNSettings{Interface: "fixtureTun", Addresses: []string{"198.18.0.1/30"}, MTU: 1500, Stack: "gvisor", AutoRoute: true}}
	state.LocalInbounds = []client.LocalInbound{{ID: lid, Name: "socks", Kind: "socks5", Listen: access.Endpoint{Host: "127.0.0.1", Port: port}}, spec}
	state.Network = P.Config{Servers: []P.DNSServer{{ID: dnsID, Name: "fixture", Type: "udp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: uint16(packet.LocalAddr().(*net.UDPAddr).Port)}, Detour: P.Action{Kind: P.Direct}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: dnsID, BootstrapServer: dnsID, Strategy: "ipv4_only", TimeoutSeconds: 2, Cache: P.DNSCachePolicy{Capacity: 4}}}
	ingress := newTUNIngress(m, spec, nil)
	ingress.lease = tunLease
	listener := &localListener{spec: spec, tun: ingress, done: make(chan struct{})}
	listener.ready.Store(true)
	m.listeners[tunID] = listener
	f := &integrationFactory{closed: make(chan string, 8), backend: x.Backend}
	r, _ := registry.NewOutbounds(f)
	prepare := func() {
		p, e := m.Prepare(ctx, state, nil, r)
		if e != nil {
			t.Fatal(e)
		}
		if e = p.Activate(); e != nil {
			t.Fatal(e)
		}
		if m.listeners[tunID] != listener || listener.tun != ingress {
			t.Fatal("TUN object recreated")
		}
	}
	dial := func() net.Conn {
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = socks.Handshake(c, socks.Connect, testfixture.Endpoint("203.0.113.1:80")); e != nil {
			c.Close()
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		return c
	}
	echo := func(c net.Conn) {
		if _, e := c.Write([]byte("live")); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 4)
		if _, e := io.ReadFull(c, b); e != nil || string(b) != "live" {
			t.Fatal("runtime echo", e)
		}
	}
	prepare()
	c1 := dial()
	defer c1.Close()
	echo(c1)
	next := "192.0.2.2"
	answer.Store(&next)
	// A changed DNS runtime and underlay endpoint must reuse the same TUN.
	state.Network.DNS.TimeoutSeconds = 3
	prepare()
	c2 := dial()
	echo(c2)
	if len(f.endpoints) != 2 || f.endpoints[0] != initial || f.endpoints[1] != next {
		t.Fatal("fresh bootstrap did not replace adapter", f.endpoints)
	}
	if !x.Backend.Has(initial) || !x.Backend.Has(next) {
		t.Fatal("effective set lost old/new protections")
	}
	echo(c1)
	answer.Store(nil)
	if p, e := m.Prepare(ctx, state, nil, r); e == nil {
		p.Abort()
		t.Fatal("empty resolution published")
	}
	if !x.Backend.Has(initial) || !x.Backend.Has(next) {
		t.Fatal("resolution failure removed old protections")
	}
	echo(c1)
	echo(c2)
	third := "192.0.2.3"
	answer.Store(&third)
	x.Backend.SetFailure(1, false)
	if p, e := m.Prepare(ctx, state, nil, r); e == nil {
		p.Abort()
		t.Fatal("protection failure published")
	}
	x.Backend.SetFailure(0, false)
	if x.Backend.Has(third) || !x.Backend.Has(next) {
		t.Fatal("partial candidate protection not compensated")
	}
	echo(c1)
	echo(c2)
	c1.Close()
	select {
	case ip := <-f.closed:
		if ip != initial {
			t.Fatal("wrong generation retired")
		}
	case <-ctx.Done():
		t.Fatal("old generation did not retire")
	}
	if e = x.Backend.WaitRemoved(ctx, initial); e != nil {
		t.Fatal(e)
	}
	if x.Backend.Has(initial) {
		t.Fatal("old protection leaked after socket retirement")
	}
	echo(c2)
	c2.Close()
	if e = m.WaitIdle(ctx); e != nil {
		t.Fatal(e)
	}
	if x.Backend.Count(underlay.ProxyUnderlay) < 2 || x.Backend.Count(underlay.DNSBootstrap) < 3 {
		t.Fatal("actual runtime escaped protected factory")
	}
	// Retire A while a second actual adapter B still owns the same IP. A
	// subsequent desired-state update retaining only B cannot delete its route.
	answer.Store(&next)
	secondNode := state.Nodes[0]
	secondNode.ID, secondNode.CredentialID, secondNode.Name = runtimeID(), runtimeID(), "shared-B"
	secondOutbound := state.Outbounds[len(state.Outbounds)-1]
	secondOutbound.ID, secondOutbound.NodeID, secondOutbound.Name = runtimeID(), &secondNode.ID, "shared-B"
	state.Nodes = append(state.Nodes, secondNode)
	state.Outbounds = append(state.Outbounds, secondOutbound)
	state.Route.DefaultOutbound = secondOutbound.ID
	prepare()
	bConn := dial()
	echo(bConn)
	state.Nodes = []client.RemoteNode{secondNode}
	state.Outbounds = []client.Outbound{state.Outbounds[0], secondOutbound}
	prepare()
	if !x.Backend.Has(next) {
		t.Fatal("A update deleted B's shared endpoint")
	}
	echo(bConn)
	bConn.Close()
	if e = m.WaitIdle(ctx); e != nil {
		t.Fatal(e)
	}
	state.Nodes = nil
	state.Outbounds = state.Outbounds[:1]
	state.Route.DefaultOutbound = client.Direct
	prepare()
	if e = x.Backend.WaitRemoved(ctx, next); e != nil {
		t.Fatal(e)
	}
	if x.Backend.Has(next) {
		t.Fatal("final B retirement leaked shared endpoint")
	}
}

type cleanupDebtDialer struct{ conn net.Conn }

func (d cleanupDebtDialer) DialContext(context.Context, access.Endpoint) (net.Conn, error) {
	return nil, errors.New("fixture retired")
}
func (d cleanupDebtDialer) Close() error { return errors.New("fixture close retained ownership") }

func TestUnderlayRetirementFailureRetainsProtectionAndReportsDebt(t *testing.T) {
	x := testkit.NewUnderlay(t)
	l, err := x.Factory.Begin(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.23")
	if err = l.AddEndpoint(context.Background(), underlay.Scope{Purpose: underlay.ProxyUnderlay}, []netip.Addr{ip}); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := &snapshot{underlay: l, outbounds: map[identity.ID]ports.ClientDialer{"direct": cleanupDebtDialer{a}}}
	s.refs.Store(1)
	if err = s.release(); err == nil {
		t.Fatal("cleanup debt ignored")
	}
	if !x.Backend.Has(ip.String()) || x.Factory.Status().Health != "degraded" || x.Factory.Status().ActiveLeases != 1 {
		t.Fatal("failed retirement released protection or hid debt")
	}
	// The fixture owner finishes closing its retained socket before releasing.
	a.Close()
	b.Close()
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
}
