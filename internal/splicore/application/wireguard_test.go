//go:build with_gvisor && with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/internal/splicore/wireguardendpoint"
	"github.com/miekg/dns"
)

type wgEcho struct{}

func (wgEcho) TCP(_ context.Context, c net.Conn, _, _ netip.AddrPort) { _, _ = io.Copy(c, c) }
func (wgEcho) UDP(_ context.Context, c net.Conn, _, _ netip.AddrPort) {
	b := make([]byte, 65535)
	for {
		n, e := c.Read(b)
		if e != nil {
			return
		}
		if _, e = c.Write(b[:n]); e != nil {
			return
		}
	}
}

func wgKeys(t *testing.T) (E.Secret, string) {
	t.Helper()
	private, public, err := application.GenerateWireGuardKeys()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := E.ParseSecret(private)
	if err != nil {
		t.Fatal(err)
	}
	return secret, public
}

func wgPeer(t *testing.T, s *application.Service, endpointHost string) (*wireguardendpoint.Endpoint, E.WireGuard, string) {
	t.Helper()
	ka, pa := wgKeys(t)
	kb, pb := wgKeys(t)
	peer, err := wireguardendpoint.New(context.Background(), E.WireGuard{Tag: "remote", PrivateKey: kb, Addresses: []string{"10.34.0.2/32", "fd34::2/128"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"0.0.0.0/0", "::/0"}}}}, wireguardendpoint.Options{Dispatcher: wgEcho{}, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err = peer.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	config := E.WireGuard{Tag: "core-wg", PrivateKey: ka, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: pb, Endpoint: net.JoinHostPort(endpointHost, strconv.Itoa(peer.Status().ListenPort)), AllowedIPs: []string{"10.34.0.2/32", "fd34::2/128"}}}}
	if _, err = s.CreateWireGuardEndpoint(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	return peer, config, pb
}

func wgTransfer(t *testing.T, e *wireguardendpoint.Endpoint, target access.Endpoint) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := e.DialContext(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("WireGuard Core ingress")
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(payload, got) {
		t.Fatalf("Core ingress integrity: %v", err)
	}
}

func wgUDP(t *testing.T, e *wireguardendpoint.Endpoint, target access.Endpoint) {
	t.Helper()
	c, err := e.ListenPacket(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	a := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(target.Host), target.Port))
	payload := []byte("WireGuard Core datagram")
	if _, err = c.WriteTo(payload, a); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 128)
	n, _, err := c.ReadFrom(got)
	if err != nil || !bytes.Equal(payload, got[:n]) {
		t.Fatalf("Core UDP ingress: %v", err)
	}
}

func wgDNS(t *testing.T, count *atomic.Int64, refreshed *atomic.Bool) access.Endpoint {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		count.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(q)
		if len(q.Question) == 1 && q.Question[0].Name == "missing.fixture.test." {
			reply.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(reply)
			return
		}
		if len(q.Question) == 1 && q.Question[0].Qtype == dns.TypeA {
			address := net.IPv4(10, 34, 0, 2)
			if q.Question[0].Name == "peer.fixture.test." {
				address = net.IPv4(127, 0, 0, 1)
				if refreshed.Load() {
					address = net.IPv4(127, 0, 0, 2)
				}
			}
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: address}}
		}
		_ = w.WriteMsg(reply)
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); <-done })
	a := pc.LocalAddr().(*net.UDPAddr)
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(a.Port)}
}

func TestPhase34WireGuardCoreRoutingDNS(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "private", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	adapters, err := registry.NewOutbounds(native.VLESSOutboundFactory{})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(ctx, adapters); err != nil {
		t.Fatal(err)
	}
	peer, config, pub := wgPeer(t, s, "peer.fixture.test")
	out := clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "create", Outbound: &client.Outbound{Name: "WireGuard endpoint", Kind: "endpoint", EndpointTag: config.Tag}}).ID
	local := freePort(t)
	addLocal(t, s, local, out)
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &client.LocalInbound{Name: "WireGuard ingress", Kind: "endpoint", EndpointTag: config.Tag, SelectedOutbound: client.Direct}})
	var queries, ambient atomic.Int64
	var refreshed atomic.Bool
	dnsEndpoint := wgDNS(t, &queries, &refreshed)
	resolver := networkID(t)
	network := P.Config{Servers: []P.DNSServer{{ID: resolver, Name: "Core DNS", Type: "udp", Endpoint: dnsEndpoint, Detour: P.Action{Kind: P.Direct}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: resolver, BootstrapServer: resolver, Strategy: "ipv4_only", TimeoutSeconds: 2, Cache: P.DNSCachePolicy{Capacity: 4}}, Route: P.RouteProfile{Rules: []P.RouteRule{{ID: networkID(t), Name: "authenticated endpoint", Match: P.RuleMatch{EndpointTags: []string{config.Tag}, PeerPublicKeys: []string{pub}}, Action: P.Action{Kind: P.Direct}}}}}
	applyNetwork(t, s, network)
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		ambient.Add(1)
		return nil, net.InvalidAddrError("ambient DNS forbidden")
	}}
	defer func() { net.DefaultResolver = old }()
	if _, err = s.StartWireGuardEndpoint(ctx, config.Tag); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"10.34.0.2", "fd34::2", "target.fixture.test"} {
		if err = transfer(local, access.Endpoint{Host: host, Port: 23434}, []byte("local to WireGuard")); err != nil {
			t.Fatal(host, err)
		}
	}
	if err = expansionUDPTraffic(local, access.Endpoint{Host: "target.fixture.test", Port: 23435}, []byte("Core managed UDP")); err != nil {
		t.Fatal(err)
	}
	// The authenticated peer sends arbitrary destinations into the normal Core
	// route. These sockets are ordinary host echo servers outside the tunnel.
	for _, ip := range []string{"192.0.2.29", "2001:db8::29"} {
		wgTransfer(t, peer, echoTarget(t, ip))
		wgUDP(t, peer, expansionUDP(t, ip))
	}
	// Hold a real flow to inspect its credential metadata while it is active.
	target := echoTarget(t, "192.0.2.29")
	c, err := peer.DialContext(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	sessions, err := s.ClientStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, session := range sessions.Sessions {
		if session.EndpointTag == config.Tag && session.PeerPublicKey == pub && session.AccountID == "" {
			found = true
		}
	}
	if !found {
		t.Fatal("safe authenticated session metadata absent")
	}
	// Whole-generation replacement joins the active flow and re-resolves the
	// endpoint through Core DNS. Borrowed outbound references follow the registry.
	refreshed.Store(true)
	time.Sleep(1100 * time.Millisecond) // expire the Core DNS TTL before explicit refresh
	replaced, err := s.ReplaceWireGuardEndpoint(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Peers[0].CurrentEndpoint != net.JoinHostPort("127.0.0.2", strconv.Itoa(peer.Status().ListenPort)) {
		t.Fatal("replacement did not use refreshed Core endpoint DNS")
	}
	if err = transfer(local, access.Endpoint{Host: "target.fixture.test", Port: 23434}, []byte("after peer generation replacement")); err != nil {
		t.Fatal(err)
	}
	failed := config.Clone()
	failed.Tag = "missing-peer"
	failed.Peers[0].Endpoint = "missing.fixture.test:51820"
	if _, err = s.CreateWireGuardEndpoint(ctx, failed); err != nil {
		t.Fatal(err)
	}
	if _, err = s.StartWireGuardEndpoint(ctx, failed.Tag); err == nil {
		t.Fatal("missing peer DNS unexpectedly started")
	}
	failedStatus, _ := s.WireGuardEndpointStatus(ctx, failed.Tag)
	if failedStatus.State != wireguardendpoint.Closed || failedStatus.UDPResources != 0 {
		t.Fatal("failed DNS retained endpoint resources")
	}
	if err = transfer(local, access.Endpoint{Host: "missing.fixture.test", Port: 23434}, []byte("no fallback")); err == nil {
		t.Fatal("missing target DNS unexpectedly routed")
	}
	if queries.Load() < 2 || ambient.Load() != 0 {
		t.Fatalf("DNS queries=%d ambient=%d", queries.Load(), ambient.Load())
	}
	status, err := s.WireGuardEndpointStatus(ctx, config.Tag)
	if err != nil || status.State != wireguardendpoint.Active {
		t.Fatal(status, err)
	}
}

func TestPhase34WireGuardToProxyAndServerToEndpoint(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			ctx := context.Background()
			s, store := setupProtocols(t, filepath.Join(t.TempDir(), "private", "state.db"), nil, registry.NativeCore)
			defer stop(t, s, store)
			c := vmessCase(t)
			if protocol == "trojan" {
				c = trojanCase(t)
			}
			if protocol == "vless" {
				for _, candidate := range expansionCases(t) {
					if candidate.name == "vless" {
						c = candidate
					}
				}
			}
			adapters, err := registry.NewOutbounds(c.factory)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.EnableClientRuntime(ctx, adapters); err != nil {
				t.Fatal(err)
			}
			peer, config, pub := wgPeer(t, s, "127.0.0.1")
			if _, err = s.StartWireGuardEndpoint(ctx, config.Tag); err != nil {
				t.Fatal(err)
			}
			tunnel := clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "create", Outbound: &client.Outbound{Name: "WireGuard endpoint", Kind: "endpoint", EndpointTag: config.Tag}}).ID
			port := freePort(t)
			created := expansionCreation(t, s, c, "127.0.0.1", port)
			node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, expansionCredential(t, store, created, 0))
			proxy := expansionProxy(t, s, node, "native")
			clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &client.LocalInbound{Name: "authenticated peer ingress", Kind: "endpoint", EndpointTag: config.Tag, SelectedOutbound: proxy}})
			// Prime the peer endpoint using ordinary local -> WireGuard routing.
			local := freePort(t)
			addLocal(t, s, local, tunnel)
			if err = transfer(local, access.Endpoint{Host: "10.34.0.2", Port: 23434}, []byte("prime peer")); err != nil {
				t.Fatal(err)
			}
			before := outboundSessions(t, s, proxy)
			wgTransfer(t, peer, echoTarget(t, "192.0.2.29"))
			wgUDP(t, peer, expansionUDP(t, "192.0.2.29"))
			if outboundSessions(t, s, proxy) < before+1 {
				t.Fatal("WireGuard TCP ingress bypassed selected proxy")
			}
			observed, _ := s.ClientStatus(ctx)
			udpObserved := false
			for _, out := range observed.Outbounds {
				if out.ID == proxy && out.Stats.UDPAssociations > 0 && out.Stats.PacketsUpload > 0 && out.Stats.PacketsDownload > 0 {
					udpObserved = true
				}
			}
			if !udpObserved {
				t.Fatal("WireGuard UDP ingress bypassed selected proxy")
			}
			// Explicit server_inbounds makes the native authenticated server enter the
			// same Core routing machinery and select the endpoint outbound.
			applyNetwork(t, s, P.Config{Route: P.RouteProfile{Rules: []P.RouteRule{{ID: networkID(t), Name: "server to WireGuard", Match: P.RuleMatch{ServerInbounds: []identity.ID{created.InboundID}, CIDRs: []string{"10.34.0.2/32"}}, Action: P.Action{Kind: P.Outbound, ID: tunnel}}, {ID: networkID(t), Name: "peer via proxy", Match: P.RuleMatch{EndpointTags: []string{config.Tag}, PeerPublicKeys: []string{pub}}, Action: P.Action{Kind: P.Outbound, ID: proxy}}}}})
			proxyLocal := freePort(t)
			addLocal(t, s, proxyLocal, proxy)
			if err = transfer(proxyLocal, access.Endpoint{Host: "10.34.0.2", Port: 23434}, []byte("server to endpoint")); err != nil {
				t.Fatal(err)
			}
			if err = expansionUDPTraffic(proxyLocal, access.Endpoint{Host: "10.34.0.2", Port: 23435}, []byte("server UDP to endpoint")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
