//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/networkruntime"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func policyObservation(t *testing.T, s *application.Service, id identity.ID, ready func(networkruntime.GroupStatus) bool) networkruntime.GroupStatus {
	t.Helper()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		st, err := s.ClientStatus(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range st.Network.Groups {
			if g.ID == id && ready(g) {
				return g
			}
		}
		select {
		case <-deadline.C:
			t.Fatal("health scheduler did not publish expected observation", st.Network.Groups)
		case <-ticker.C:
		}
	}
}
func outboundSessions(t *testing.T, s *application.Service, id identity.ID) int64 {
	t.Helper()
	st, err := s.ClientStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range st.Outbounds {
		if o.ID == id {
			return o.Stats.Sessions
		}
	}
	t.Fatal("missing outbound")
	return 0
}
func heldUDP(t *testing.T, port uint16, target access.Endpoint) net.PacketConn {
	t.Helper()
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = control.SetDeadline(time.Now().Add(15 * time.Second))
	response, err := socks.ClientHandshake5(control, socks5.CommandUDPAssociate, M.ParseSocksaddr("0.0.0.0:0"), "", "")
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	udp, err := net.Dial("udp", response.Bind.String())
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	return socks.NewAssociatePacketConn(udp, M.ParseSocksaddrHostPort(target.Host, target.Port), control)
}
func checkUDP(t *testing.T, pc net.PacketConn, target access.Endpoint, payload string) {
	t.Helper()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.WriteTo([]byte(payload), M.ParseSocksaddrHostPort(target.Host, target.Port)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65535)
	n, _, err := pc.ReadFrom(b)
	if err != nil || !bytes.Equal(b[:n], []byte(payload)) {
		t.Fatal("UDP integrity/affinity", err)
	}
}
func TestPhase12RoutingDNSPolicyAcceptance(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupProtocols(t, path, nil, phase8Protocols)
	defer func() { stop(t, s, store) }()
	cases := expansionCases(t)
	factories := []ports.OutboundFactory{}
	for _, c := range cases {
		factories = append(factories, c.factory)
	}
	adapters, err := registry.NewOutbounds(factories...)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(ctx, adapters); err != nil {
		t.Fatal(err)
	}
	// Three controlled, real Splicore server/client adapters; all remain active together.
	members := []P.Action{}
	var primaryInbound, primaryBinding identity.ID
	for _, c := range cases[:3] {
		remote := freePort(t)
		if c.transport == "quic" {
			remote = udpPort(t)
		}
		created := expansionCreation(t, s, c, "127.0.0.1", remote)
		if c.name == "hysteria2" {
			primaryInbound = created.InboundID
			primaryBinding = created.Bindings[0].BindingID
		}
		node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: remote}, expansionCredential(t, store, created, 0))
		members = append(members, P.Action{Kind: P.Outbound, ID: expansionProxy(t, s, node, "native")})
	}
	local := freePort(t)
	in := addLocal(t, s, local, "")
	tcp4, tcp6 := echoTarget(t, "127.0.0.1"), echoTarget(t, "::1")
	udp1, udp2 := expansionUDP(t, "127.0.0.1"), expansionUDP(t, "127.0.0.1")
	var directQueries, proxyQueries atomic.Int64
	directDNS, proxyDNS := appDNS(t, "udp", &directQueries), appDNS(t, "tcp", &proxyQueries)
	selector, lb, urlTest, fallback := networkID(t), networkID(t), networkID(t), networkID(t)
	resolverA, resolverB := networkID(t), networkID(t)
	c := P.Config{Groups: []P.PolicyGroup{{ID: selector, Name: "selector", Type: "selector", Members: members, Selector: &P.SelectorSettings{Selected: members[0]}}},
		Servers:  []P.DNSServer{{ID: resolverA, Name: "direct DNS", Type: "udp", Endpoint: directDNS, Detour: P.Action{Kind: P.Direct}}, {ID: resolverB, Name: "proxy DNS", Type: "tcp", Endpoint: proxyDNS, Detour: P.Action{Kind: P.Group, ID: selector}}},
		DNSRules: []P.DNSRule{{ID: networkID(t), Name: "proxy split", Match: P.RuleMatch{Suffixes: []string{"proxy.local"}}, Server: resolverB}},
		DNS:      P.DNSProfile{Enabled: true, DefaultServer: resolverA, BootstrapServer: resolverA, Strategy: "ipv4_only", Cache: P.DNSCachePolicy{Capacity: 32}, TimeoutSeconds: 3},
		Route: P.RouteProfile{Final: &P.Action{Kind: P.Direct}, Rules: []P.RouteRule{
			{ID: networkID(t), Name: "domain selector", Match: P.RuleMatch{Suffixes: []string{"example.local"}}, Action: P.Action{Kind: P.Group, ID: selector}},
		}}}
	applyNetwork(t, s, c)
	t.Run("A_DomainSelectorSnellAndDIRECT", func(t *testing.T) {
		before := outboundSessions(t, s, members[0].ID)
		target := tcp4
		target.Host = "a.example.local"
		if err := transfer(local, target, []byte("domain Snell")); err != nil {
			t.Fatal(err)
		}
		target.Host = "other.local"
		if err := transfer(local, target, []byte("domain DIRECT")); err != nil {
			t.Fatal(err)
		}
		waitIdle(t, s)
		if outboundSessions(t, s, members[0].ID) != before+1 {
			t.Fatal("domain did not use Snell")
		}
		count := directQueries.Load() + proxyQueries.Load()
		q := networkruntime.Query{Domain: "a.example.local", Port: tcp4.Port, Network: "tcp", LocalInbound: in}
		explanation, err := s.RouteExplain(ctx, q)
		if err != nil || explanation.Selected != members[0] || count != directQueries.Load()+proxyQueries.Load() {
			t.Fatal(explanation, err)
		}
	})
	t.Run("B_IPv4HY2IPv6TUIC", func(t *testing.T) {
		c.Route.Rules = append(c.Route.Rules, P.RouteRule{ID: networkID(t), Name: "IPv4", Match: P.RuleMatch{CIDRs: []string{"127.0.0.0/8"}}, Action: members[1]}, P.RouteRule{ID: networkID(t), Name: "IPv6", Match: P.RuleMatch{CIDRs: []string{"::1/128"}}, Action: members[2]})
		applyNetwork(t, s, c)
		a, b := outboundSessions(t, s, members[1].ID), outboundSessions(t, s, members[2].ID)
		if err := transfer(local, tcp4, []byte("HY2 CIDR")); err != nil {
			t.Fatal(err)
		}
		if err := transfer(local, tcp6, []byte("TUIC CIDR")); err != nil {
			t.Fatal(err)
		}
		waitIdle(t, s)
		if outboundSessions(t, s, members[1].ID) != a+1 || outboundSessions(t, s, members[2].ID) != b+1 {
			t.Fatal("CIDR selected wrong outbound")
		}
		explanation, err := s.RouteExplain(ctx, networkruntime.Query{Domain: "original.local", Resolved: []netip.Addr{netip.MustParseAddr("::1")}, Port: tcp6.Port, Network: "tcp"})
		if err != nil || explanation.Selected != members[2] {
			t.Fatal("resolved IPv6 metadata", explanation, err)
		}
	})
	var probeRequests atomic.Int64
	var primaryDown atomic.Bool
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeRequests.Add(1)
		if primaryDown.Load() {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer probe.Close()
	probeSettings := P.Probe{URL: probe.URL, IntervalSeconds: 1, TimeoutSeconds: 2, ExpectedStatus: 204}
	t.Run("C_ThreeRealOutboundURLTest", func(t *testing.T) {
		c.Groups = append(c.Groups, P.PolicyGroup{ID: urlTest, Name: "URL-Test", Type: "url_test", Members: members, URLTest: &P.URLTestSettings{Probe: probeSettings}})
		applyNetwork(t, s, c)
		g := policyObservation(t, s, urlTest, func(g networkruntime.GroupStatus) bool {
			for _, m := range g.Members {
				if m.Health.State != "healthy" {
					return false
				}
			}
			return true
		})
		expected := g.Members[0].Member
		best := int64(1 << 62)
		for _, m := range g.Members {
			if m.Health.LatencyMS < best {
				best = m.Health.LatencyMS
				expected = m.Member
			}
		}
		if g.Selected != expected || probeRequests.Load() < 3 {
			t.Fatal("HTTP latency selection", g)
		}
	})
	t.Run("D_FallbackDownAndRecovery", func(t *testing.T) {
		c.Groups = append(c.Groups, P.PolicyGroup{ID: fallback, Name: "Fallback", Type: "fallback", Members: []P.Action{members[1], members[0], members[2]}, Fallback: &P.FallbackSettings{Probe: probeSettings}})
		applyNetwork(t, s, c)
		policyObservation(t, s, fallback, func(g networkruntime.GroupStatus) bool { return g.Available && g.Selected == members[1] })
		changePrimary := func(enabled bool) {
			t.Helper()
			bindings, err := store.Bindings(ctx, primaryInbound)
			if err != nil {
				t.Fatal(err)
			}
			state, err := store.State(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range bindings {
				if b.ID == primaryBinding {
					_, err = s.SetBinding(ctx, primaryInbound, application.BindingRequest{BindingID: b.ID, Enabled: enabled, ResourceRevision: b.Revision, Revision: state.Revision})
					if err != nil {
						t.Fatal(err)
					}
					return
				}
			}
			t.Fatal("missing primary binding")
		}
		changePrimary(false)
		policyObservation(t, s, fallback, func(g networkruntime.GroupStatus) bool { return g.Available && g.Selected == members[0] })
		changePrimary(true)
		policyObservation(t, s, fallback, func(g networkruntime.GroupStatus) bool { return g.Available && g.Selected == members[1] })
		// Every member returning an unexpected status makes the group unavailable.
		primaryDown.Store(true)
		policyObservation(t, s, fallback, func(g networkruntime.GroupStatus) bool { return !g.Available })
		primaryDown.Store(false)
		policyObservation(t, s, fallback, func(g networkruntime.GroupStatus) bool { return g.Available && g.Selected == members[1] })

	})
	t.Run("E_RoundRobinAndUDPAssociationAffinity", func(t *testing.T) {
		c.Groups = append(c.Groups, P.PolicyGroup{ID: lb, Name: "round robin", Type: "load_balance", Members: members, LoadBalance: &P.LoadBalanceSettings{Algorithm: "round_robin"}})
		c.Route.Rules = append([]P.RouteRule{{ID: networkID(t), Name: "balanced local", Match: P.RuleMatch{LocalInbounds: []identity.ID{in}}, Action: P.Action{Kind: P.Group, ID: lb}}}, c.Route.Rules...)
		applyNetwork(t, s, c)
		before := []int64{}
		for _, m := range members {
			before = append(before, outboundSessions(t, s, m.ID))
		}
		for range 6 {
			if err := transfer(local, tcp4, []byte("round robin")); err != nil {
				t.Fatal(err)
			}
		}
		waitIdle(t, s)
		for i, m := range members {
			if outboundSessions(t, s, m.ID) != before[i]+2 {
				t.Fatal("distribution", i)
			}
		}
		pc := heldUDP(t, local, udp1)
		defer pc.Close()
		for i := range 10 {
			checkUDP(t, pc, udp1, fmt.Sprint("affinity-", i))
			checkUDP(t, pc, udp2, fmt.Sprint("second-flow-", i))
		}
		st, _ := s.ClientStatus(ctx)
		for _, g := range st.Network.Groups {
			if g.ID == lb && g.Selections != 7 {
				t.Fatal("UDP flow/packet advanced RR", g)
			}
		}
	})
	t.Run("F_DNSSplitProxyNoLeak", func(t *testing.T) {
		_ = s.FlushDNS(ctx)
		beforeA, beforeB := directQueries.Load(), proxyQueries.Load()
		r, err := s.DNSLookup(ctx, "split.proxy.local")
		if err != nil || r.Server != resolverB || directQueries.Load() != beforeA || proxyQueries.Load() != beforeB+1 {
			t.Fatal("proxy DNS leak", r, err)
		}
		_, err = s.DNSLookup(ctx, "split.direct.local")
		if err != nil || directQueries.Load() != beforeA+1 || proxyQueries.Load() != beforeB+1 {
			t.Fatal("direct DNS leak", err)
		}
	})
	t.Run("G_Atomic100RulesGroupDNSOldTCPAndUDP", func(t *testing.T) {
		c.Route.Rules = c.Route.Rules[1:]
		applyNetwork(t, s, c)
		domainTarget := tcp4
		domainTarget.Host = "held.example.local"
		oldTCP, err := socksConn(local, domainTarget)
		if err != nil {
			t.Fatal(err)
		}
		defer oldTCP.Close()
		checkHeld(t, oldTCP, "old TCP")
		udpTarget := udp1
		udpTarget.Host = "held.example.local"
		oldUDP := heldUDP(t, local, udpTarget)
		defer oldUDP.Close()
		checkUDP(t, oldUDP, udpTarget, "old UDP")
		changed := c.Clone()
		changed.Groups[0].Selector.Selected = members[2]
		changed.DNSRules = append(changed.DNSRules, P.DNSRule{ID: networkID(t), Name: "changed DNS", Match: P.RuleMatch{Suffixes: []string{"example.local"}}, Server: resolverB})
		rules := []P.RouteRule{}
		for i := range 100 {
			rules = append(rules, P.RouteRule{ID: networkID(t), Name: fmt.Sprint("atomic-", i), Match: P.RuleMatch{Domains: []string{fmt.Sprintf("unused-%d.local", i)}}, Action: P.Action{Kind: P.Reject}})
		}
		changed.Route.Rules = append(rules, changed.Route.Rules...)
		// Traffic crosses the commit, then is checked after publication.
		var wg sync.WaitGroup
		fail := make(chan error, 1)
		wg.Go(func() {
			for range 8 {
				if _, err := oldTCP.Write([]byte("tick")); err != nil {
					fail <- err
					return
				}
				b := make([]byte, 4)
				if _, err := io.ReadFull(oldTCP, b); err != nil {
					fail <- err
					return
				}
				if string(b) != "tick" {
					fail <- fmt.Errorf("mixed old snapshot")
					return
				}
			}
		})
		applyNetwork(t, s, changed)
		wg.Wait()
		select {
		case err := <-fail:
			t.Fatal(err)
		default:
		}
		checkHeld(t, oldTCP, "survived update")
		checkUDP(t, oldUDP, udpTarget, "UDP survived update")
		// A newly created flow in the old association also uses its old generation/member.
		second := udp2
		second.Host = "new-flow.example.local"
		checkUDP(t, oldUDP, second, "old association new flow")
		before := outboundSessions(t, s, members[2].ID)
		if err := transfer(local, domainTarget, []byte("new TUIC")); err != nil {
			t.Fatal(err)
		}
		if outboundSessions(t, s, members[2].ID) != before+1 {
			t.Fatal("new TCP did not change selector")
		}
		st, _ := s.ClientStatus(ctx)
		for _, session := range st.Sessions {
			if session.Kind == "udp_association" && session.OutboundID != members[0].ID {
				t.Fatal("old UDP moved", session)
			}
		}
		c = changed
	})
	t.Run("H_ServerClientCoexistenceAndRestart", func(t *testing.T) {
		waitIdle(t, s)
		before, _ := s.System(ctx)
		if len(before.ServerRuntimes) != 3 {
			t.Fatal("server coexistence")
		}
		stop(t, s, store)
		s, store = setupProtocols(t, path, nil, phase8Protocols)
		if err := s.EnableClientRuntime(ctx, adapters); err != nil {
			t.Fatal(err)
		}
		restored, _ := s.ClientStatus(ctx)
		if len(restored.State.Network.Route.Rules) != 103 || restored.State.Network.Groups[0].Selector.Selected != members[2] || len(restored.State.Network.DNSRules) != 2 {
			t.Fatal("graph recovery")
		}
		domainTarget := tcp4
		domainTarget.Host = "restart.example.local"
		if err := transfer(local, domainTarget, []byte("restart TUIC")); err != nil {
			t.Fatal(err)
		}
		if err := expansionUDPTraffic(local, udp1, []byte("restart UDP HY2")); err != nil {
			t.Fatal(err)
		}
		waitIdle(t, s)
		after, _ := s.System(ctx)
		if len(after.ServerRuntimes) != 3 {
			t.Fatal("server graph lost")
		}
	})
}
