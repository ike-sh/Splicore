package hostnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
)

func bypassUnderlays() map[bool]WindowsUnderlay {
	return map[bool]WindowsUnderlay{true: {InterfaceGUID: "00000000-0000-4000-8000-000000000001", Index: 7, NextHop: netip.MustParseAddr("192.0.2.1"), Metric: 17}, false: {InterfaceGUID: "00000000-0000-4000-8000-000000000002", Index: 8, NextHop: netip.MustParseAddr("2001:db8::1"), Metric: 18}}
}
func TestWindowsBypassDependencyMatrix(t *testing.T) {
	ctx := context.Background()
	u := bypassUnderlays()
	deps := []WindowsDependency{
		{ID: "v4", Reason: "node", Host: "192.0.2.11"}, {ID: "v6", Reason: "node", Host: "2001:db8::11"}, {ID: "mapped", Reason: "node", Host: "::ffff:192.0.2.11"},
		{ID: "domain", Reason: "node", Host: "node.fixture.test", Requires: []string{"bootstrap"}},
		{ID: "second-node", Reason: "node", Host: "192.0.2.12"}, {ID: "bootstrap", Reason: "dns-bootstrap", Host: "192.0.2.53"},
		{ID: "upstream", Reason: "dns-upstream", Host: "dns.fixture.test", Requires: []string{"bootstrap"}},
		{ID: "health", Reason: "health", Host: "health.fixture.test", Requires: []string{"bootstrap"}},
		{ID: "control", Reason: "control", Host: "127.0.0.1"},
	}
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		values := map[string][]netip.Addr{"node.fixture.test": {netip.MustParseAddr("192.0.2.13"), netip.MustParseAddr("2001:db8::13")}, "dns.fixture.test": {netip.MustParseAddr("192.0.2.54")}, "health.fixture.test": {netip.MustParseAddr("192.0.2.55")}}
		return values[host], nil
	}
	plan, err := BuildWindowsBypassPlan(ctx, deps, u, resolve)
	if err != nil || len(plan.Routes) != 8 {
		t.Fatal(err, plan)
	}
	if !slices.Contains(plan.Routes[0].Reasons, "node:mapped") || len(plan.Routes[0].Reasons) != 2 {
		t.Fatal("mapped normalization/shared reference", plan)
	}
	copyBefore := append([]string(nil), plan.Routes[0].Reasons...)
	deps[0].ID = "changed"
	if !reflect.DeepEqual(copyBefore, plan.Routes[0].Reasons) {
		t.Fatal("caller mutation changed plan")
	}
	for _, kind := range []string{"node-resolver-outbound-node", "probe-group-dns-group", "node-dns-tun-node"} {
		graph := []WindowsDependency{{ID: "a", Reason: "node", Host: "node.fixture.test", Requires: []string{"b"}}, {ID: "b", Reason: "dns-upstream", Requires: []string{"c"}}, {ID: "c", Reason: "outbound", Requires: []string{"a"}}}
		called := false
		_, err = BuildWindowsBypassPlan(ctx, graph, u, func(context.Context, string) ([]netip.Addr, error) { called = true; return nil, nil })
		if err == nil || called {
			t.Fatal(kind, "cycle reached resolution")
		}
	}
}
func TestWindowsCanonicalProfileDependencyProjection(t *testing.T) {
	id := func(n string) identity.ID { return identity.ID("00000000-0000-4000-8000-00000000000" + n) }
	state := client.Empty()
	nid, oid, resolver := id("1"), id("2"), id("3")
	state.Nodes = []client.RemoteNode{{ID: nid, Endpoint: access.Endpoint{Host: "node.fixture.test", Port: 443}}}
	state.Outbounds = append(state.Outbounds, client.Outbound{ID: oid, NodeID: &nid, Engine: "native"})
	if _, e := WindowsProfileDependencies(state, nil); e == nil {
		t.Fatal("unknown system bootstrap accepted")
	}
	d, e := WindowsProfileDependencies(state, []netip.Addr{netip.MustParseAddr("192.0.2.53")})
	if e != nil {
		t.Fatal(e)
	}
	if !slices.ContainsFunc(d, func(v WindowsDependency) bool { return v.ID == "node:"+string(nid) }) {
		t.Fatal("Native ownership omitted")
	}
	plan, err := BuildWindowsBypassPlan(context.Background(), d, bypassUnderlays(), func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.11")}, nil
	})
	if err != nil || !slices.ContainsFunc(plan.Routes, func(r WindowsRouteState) bool { return slices.Contains(r.Reasons, "node:node:"+string(nid)) }) {
		t.Fatal("Native endpoint route ownership omitted", err)
	}
	state.Network.DNS.Enabled = true
	state.Network.DNS.BootstrapServer = resolver
	state.Network.Servers = []P.DNSServer{{ID: resolver, Type: "udp", Endpoint: access.Endpoint{Host: "192.0.2.53", Port: 53}, Detour: P.Action{Kind: P.Outbound, ID: oid}}}
	if _, e = WindowsProfileDependencies(state, nil); e == nil {
		t.Fatal("canonical node/resolver/outbound cycle accepted")
	}
	state.Network.Servers[0].Detour = P.Action{Kind: P.Direct}
	if _, e = WindowsProfileDependencies(state, nil); e != nil {
		t.Fatal(e)
	}
}

func TestWindowsBypassFreshDomainResolutionAndSharedReferences(t *testing.T) {
	ctx := context.Background()
	b := newWindowsRouteFixture()
	s := &memoryStore{}
	m, _ := New(b, s)
	address := "192.0.2.11"
	calls := 0
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr(address)}, nil
	}
	dependencies := []WindowsDependency{{ID: "A", Reason: "node", Host: "node.fixture.test"}, {ID: "B", Reason: "node", Host: "192.0.2.11"}}
	first, err := BuildWindowsBypassPlan(ctx, dependencies, bypassUnderlays(), resolve)
	if err != nil {
		t.Fatal(err)
	}
	l, err := m.Prepare(ctx, first.Records(), nil)
	if err != nil {
		t.Fatal(err)
	}
	address = "192.0.2.12"
	next, err := BuildWindowsBypassPlan(ctx, dependencies, bypassUnderlays(), resolve)
	if err != nil || calls != 2 {
		t.Fatal("domain fixed to initial snapshot", err)
	}
	if err = l.ReconcileWindowsBypass(ctx, next); err != nil {
		t.Fatal(err)
	}
	if b.state["windows-route:192.0.2.11/32"] == nil {
		t.Fatal("B's shared protection deleted")
	}
	if !reflect.DeepEqual(b.events[len(b.events)-1:], []string{"add:192.0.2.12/32"}) {
		t.Fatal("new protection not installed first", b.events)
	}
	next, err = BuildWindowsBypassPlan(ctx, dependencies[:1], bypassUnderlays(), resolve)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ReconcileWindowsBypass(ctx, next); err != nil || b.state["windows-route:192.0.2.11/32"] != nil {
		t.Fatal("unreferenced old IP retained", err)
	}
	if err = l.Restore(ctx); err != nil {
		t.Fatal(err)
	}
}

type windowsRouteFixture struct {
	*fixtureBackend
	events      []string
	restoreFail int
	removes     int
}

func (b *windowsRouteFixture) OwnershipRecords(g, o identity.ID, r []Record) ([]Record, error) {
	return windowsOwnershipRecords(g, o, r)
}
func (b *windowsRouteFixture) Authorize(Generation) error { return nil }
func (b *windowsRouteFixture) Read(ctx context.Context, r Record) (*Record, error) {
	v, e := b.fixtureBackend.Read(ctx, r)
	if v != nil && v.WindowsRoute != nil {
		v.WindowsRoute.Generation = r.WindowsRoute.Generation
		v.WindowsRoute.Owner = r.WindowsRoute.Owner
		v.WindowsRoute.Reasons = append([]string(nil), r.WindowsRoute.Reasons...)
	}
	return v, e
}
func (b *windowsRouteFixture) Write(ctx context.Context, k Record, v *Record) error {
	verb := "add:"
	if v == nil {
		verb = "remove:"
		b.removes++
		if b.removes == b.restoreFail {
			return errors.New("remove failure")
		}
	}
	b.events = append(b.events, verb+k.WindowsRoute.Destination)
	return b.fixtureBackend.Write(ctx, k, v)
}
func newWindowsRouteFixture() *windowsRouteFixture {
	return &windowsRouteFixture{fixtureBackend: &fixtureBackend{state: map[string]*Record{}}}
}
func bypassPlan(t *testing.T, values map[string]string) WindowsBypassPlan {
	t.Helper()
	var deps []WindowsDependency
	for id, ip := range values {
		deps = append(deps, WindowsDependency{ID: id, Reason: "node", Host: ip})
	}
	p, e := BuildWindowsBypassPlan(context.Background(), deps, bypassUnderlays(), nil)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestWindowsBypassDynamicReconciliationAndBorrowedRoutes(t *testing.T) {
	ctx := context.Background()
	a := bypassPlan(t, map[string]string{"A": "192.0.2.11", "B": "192.0.2.11"})
	b := newWindowsRouteFixture()
	s := &memoryStore{}
	m, _ := New(b, s)
	l, err := m.Prepare(ctx, a.Records(), nil)
	if err != nil {
		t.Fatal(err)
	}
	next := bypassPlan(t, map[string]string{"A": "192.0.2.12", "B": "192.0.2.11"})
	if err = l.ReconcileWindowsBypass(ctx, next); err != nil {
		t.Fatal(err)
	}
	if b.state["windows-route:192.0.2.11/32"] == nil || b.state["windows-route:192.0.2.12/32"] == nil || b.removes != 0 {
		t.Fatal("shared route removed")
	}
	next = bypassPlan(t, map[string]string{"A": "192.0.2.12"})
	if err = l.ReconcileWindowsBypass(ctx, next); err != nil {
		t.Fatal(err)
	}
	if b.state["windows-route:192.0.2.11/32"] != nil {
		t.Fatal("unused owned route retained")
	}
	if err = l.ReconcileWindowsBypass(ctx, a); err != nil {
		t.Fatal("re-add former IP", err)
	}
	if _, err = DecodeJournal(s.data); err != nil {
		t.Fatal(err)
	}
	if err = l.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	for _, v := range b.state {
		if v != nil {
			t.Fatal("owned route survived stop")
		}
	}
	// An identical pre-existing route is borrowed without Add or Delete.
	b = newWindowsRouteFixture()
	records := a.Records()
	g, _ := identity.NewID()
	o, _ := identity.NewID()
	records, _ = windowsOwnershipRecords(g, o, records)
	b.state[records[0].key()] = cloneRecord(&records[0])
	s = &memoryStore{}
	m, _ = New(b, s)
	l, err = m.Prepare(ctx, a.Records(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.events) != 0 {
		t.Fatal("borrowed route rewritten")
	}
	if m.Status().OwnedRoutes != 0 {
		t.Fatal("borrowed route reported as owned")
	}
	if err = l.ReconcileWindowsBypass(ctx, WindowsBypassPlan{}); err != nil {
		t.Fatal(err)
	}
	if err = l.Restore(ctx); err != nil || b.state[records[0].key()] == nil || len(b.events) != 0 {
		t.Fatal("pre-existing route deleted", err)
	}
}
func TestWindowsBypassReconciliationFailures(t *testing.T) {
	ctx := context.Background()
	a := bypassPlan(t, map[string]string{"A": "192.0.2.11", "B": "192.0.2.13"})
	next := bypassPlan(t, map[string]string{"A": "192.0.2.12"})
	for _, fault := range []string{"journal-intent", "new-route", "journal-ack", "old-remove", "second-old-remove"} {
		b := newWindowsRouteFixture()
		s := &memoryStore{}
		m, _ := New(b, s)
		l, err := m.Prepare(ctx, a.Records(), nil)
		if err != nil {
			t.Fatal(err)
		}
		switch fault {
		case "journal-intent":
			s.fail = s.saves + 1
		case "new-route":
			b.fail = b.writes + 1
		case "journal-ack":
			s.fail = s.saves + 2
		case "old-remove":
			b.restoreFail = 1
		case "second-old-remove":
			b.restoreFail = 2
		}
		if err = l.ReconcileWindowsBypass(ctx, next); err == nil {
			t.Fatal(fault, "not surfaced")
		}
		for _, r := range a.Routes {
			if b.state["windows-route:"+r.Destination] == nil {
				t.Fatal(fault, "old protection lost")
			}
		}
		if b.state["windows-route:192.0.2.12/32"] != nil {
			t.Fatal(fault, "new route retained")
		}
		b.fail = 0
		s.fail = 0
		b.restoreFail = 0
		if err = m.Recover(ctx); err != nil {
			t.Fatal(fault, err)
		}
	}
	b := newWindowsRouteFixture()
	s := &memoryStore{}
	m, _ := New(b, s)
	l, _ := m.Prepare(ctx, a.Records(), nil)
	b.state["windows-route:192.0.2.11/32"].WindowsRoute.Metric++
	if err := l.ReconcileWindowsBypass(ctx, next); err == nil {
		t.Fatal("external edit overwritten")
	}
	if b.state["windows-route:192.0.2.11/32"].WindowsRoute.Metric != 18 {
		t.Fatal("external route not preserved")
	}
	if m.Status().Recovery != "degraded" || m.journal.Generations[0].State != "conflict" {
		t.Fatal("external conflict silently left active", m.Status())
	}
	if err := l.ReconcileWindowsBypass(ctx, a); err == nil {
		t.Fatal("conflicted protection admitted a new update")
	}
}

func TestWindowsBypassFinalAckFailureAndRepeatedChurn(t *testing.T) {
	ctx := context.Background()
	b := newWindowsRouteFixture()
	s := &memoryStore{}
	m, _ := New(b, s)
	a := bypassPlan(t, map[string]string{"A": "192.0.2.11"})
	l, err := m.Prepare(ctx, a.Records(), nil)
	if err != nil {
		t.Fatal(err)
	}
	next := bypassPlan(t, map[string]string{"A": "192.0.2.12"})
	// intent, add acknowledgment, removal intent, removal acknowledgment,
	// final metadata acknowledgment. Fail the last one after kernel changes.
	s.fail = s.saves + 5
	if err = l.ReconcileWindowsBypass(ctx, next); err == nil {
		t.Fatal("final journal failure ignored")
	}
	if b.state["windows-route:192.0.2.11/32"] == nil || b.state["windows-route:192.0.2.12/32"] != nil {
		t.Fatal("last acknowledgment failure did not compensate routes")
	}
	if m.Status().Recovery != "degraded" {
		t.Fatal("journal failure lost")
	}
	s.fail = 0
	if err = m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	l, err = m.Prepare(ctx, a.Records(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 600; i++ {
		plan := a
		if i%2 == 0 {
			plan = next
		}
		if err = l.ReconcileWindowsBypass(ctx, plan); err != nil {
			t.Fatal(i, err)
		}
		if len(m.journal.Generations[len(m.journal.Generations)-1].Steps) > 2 {
			t.Fatal("unbounded completed history")
		}
	}
	if err = l.Restore(ctx); err != nil {
		t.Fatal(err)
	}
}
func FuzzWindowsEndpointNormalization(f *testing.F) {
	f.Add("192.0.2.11")
	f.Add("::ffff:192.0.2.11")
	f.Add("2001:db8::11")
	f.Fuzz(func(t *testing.T, s string) {
		ip, e := netip.ParseAddr(s)
		if e != nil {
			return
		}
		n, e := NormalizeWindowsEndpoint(ip)
		if e != nil {
			return
		}
		again, e := NormalizeWindowsEndpoint(n)
		if e != nil || n != again || n.Is4In6() {
			t.Fatal("noncanonical normalization")
		}
	})
}
func FuzzWindowsBypassDesiredSet(f *testing.F) {
	f.Add("192.0.2.11", "::ffff:192.0.2.11")
	f.Fuzz(func(t *testing.T, a, b string) {
		ips := []string{a, b}
		deps := []WindowsDependency{}
		for i, s := range ips {
			ip, e := netip.ParseAddr(s)
			if e != nil {
				return
			}
			n, e := NormalizeWindowsEndpoint(ip)
			if e != nil {
				return
			}
			deps = append(deps, WindowsDependency{ID: []string{"A", "B"}[i], Reason: "node", Addresses: []netip.Addr{n}})
		}
		p, e := BuildWindowsBypassPlan(context.Background(), deps, bypassUnderlays(), nil)
		if e != nil {
			return
		}
		seen := map[string]bool{}
		for _, r := range p.Routes {
			if seen[r.Destination] {
				t.Fatal("duplicate desired route")
			}
			seen[r.Destination] = true
		}
		encoded, _ := json.Marshal(p)
		var clone WindowsBypassPlan
		json.Unmarshal(encoded, &clone)
		if !reflect.DeepEqual(p, clone) {
			t.Fatal("mutable snapshot roundtrip")
		}
	})
}
