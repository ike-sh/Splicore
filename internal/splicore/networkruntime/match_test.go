package networkruntime

import (
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"net/netip"
	"sync"
	"testing"
)

func testID(n int) identity.ID { return identity.ID(fmt.Sprintf("00000000-0000-4000-8000-%012d", n)) }
func TestOrderedRulesAndResolvedMetadata(t *testing.T) {
	cases := []struct {
		name    string
		match   P.RuleMatch
		yes, no Query
	}{
		{"exact", P.RuleMatch{Domains: []string{"EXAMPLE.test"}}, Query{Domain: "example.test."}, Query{Domain: "a.example.test"}},
		{"suffix", P.RuleMatch{Suffixes: []string{"example.test"}}, Query{Domain: "a.example.test"}, Query{Domain: "badexample.test"}},
		{"keyword", P.RuleMatch{Keywords: []string{"ample"}}, Query{Domain: "example.test"}, Query{Domain: "other.test"}},
		{"IPv4", P.RuleMatch{CIDRs: []string{"127.0.0.0/8"}}, Query{IP: netip.MustParseAddr("127.0.0.1")}, Query{IP: netip.MustParseAddr("::1")}},
		{"IPv6", P.RuleMatch{CIDRs: []string{"::1/128"}}, Query{Domain: "original.test", Resolved: []netip.Addr{netip.MustParseAddr("::1")}}, Query{IP: netip.MustParseAddr("127.0.0.1")}},
		{"ports", P.RuleMatch{Ports: []P.PortRange{{Start: 80, End: 90}}}, Query{Port: 85}, Query{Port: 91}},
		{"network", P.RuleMatch{Networks: []string{"udp"}}, Query{Network: "udp"}, Query{Network: "tcp"}},
		{"local", P.RuleMatch{LocalInbounds: []identity.ID{testID(1)}}, Query{LocalInbound: testID(1)}, Query{LocalInbound: testID(2)}},
		{"AND", P.RuleMatch{Suffixes: []string{"example.test"}, Ports: []P.PortRange{{Start: 80, End: 80}}}, Query{Domain: "example.test", Port: 80}, Query{Domain: "example.test", Port: 81}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := P.Config{Route: P.RouteProfile{Rules: []P.RouteRule{{ID: testID(3), Match: tt.match, Action: P.Action{Kind: P.Reject}}, {ID: testID(4), Action: P.Action{Kind: P.Direct}}}}}
			m, err := Compile(c)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Match(tt.yes, P.Action{}, true); got.Rule != testID(3) {
				t.Fatal(got)
			}
			if got := m.Match(tt.no, P.Action{}, true); got.Rule != testID(4) {
				t.Fatal(got)
			}
			if hits := m.Hits(); hits[0].Hits != 1 || hits[1].Hits != 1 {
				t.Fatal(hits)
			}
			_ = m.Match(tt.yes, P.Action{}, false)
			if m.Hits()[0].Hits != 1 {
				t.Fatal("explain counted")
			}
		})
	}
}
func TestRuleSetOwnershipAndConcurrentHits(t *testing.T) {
	c := P.Config{RuleSets: []P.RuleSet{{ID: testID(1), Status: "enabled", Rules: []P.RuleMatch{{Suffixes: []string{"owned.test"}}}}},
		Route: P.RouteProfile{Rules: []P.RouteRule{{ID: testID(2), Match: P.RuleMatch{RuleSets: []identity.ID{testID(1)}}, Action: P.Action{Kind: P.Reject}}}}}
	m, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	c.RuleSets[0].Rules[0].Suffixes[0] = "changed.test"
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				v := m.Match(Query{Domain: "owned.test"}, P.Action{Kind: P.Direct}, true)
				if v.Rule != testID(2) || len(v.RuleSets) != 1 {
					t.Error(v)
				}
			}
		})
	}
	wg.Wait()
	if m.Hits()[0].Hits != 1600 {
		t.Fatal(m.Hits())
	}
}
func BenchmarkRouteCompilation(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := syntheticRules(n)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, err := Compile(c)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
func BenchmarkRouteMatch(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			m, _ := Compile(syntheticRules(n))
			q := Query{Domain: "no-match.synthetic.test", Port: 443, Network: "tcp"}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = m.Match(q, P.Action{Kind: P.Direct}, true)
			}
		})
	}
}
func syntheticRules(n int) P.Config {
	c := P.Config{}
	for i := range n {
		c.Route.Rules = append(c.Route.Rules, P.RouteRule{ID: testID(i + 1), Name: "synthetic", Match: P.RuleMatch{Domains: []string{fmt.Sprintf("rule%d.synthetic.test", i)}}, Action: P.Action{Kind: P.Reject}})
	}
	return c
}

func FuzzRuleCompilation(f *testing.F) {
	f.Add("synthetic.test", "127.0.0.0/8", uint16(443))
	f.Add("UPPER.test.", "::1/128", uint16(1))
	f.Fuzz(func(t *testing.T, domain, cidr string, port uint16) {
		c := P.Config{Route: P.RouteProfile{Rules: []P.RouteRule{{ID: testID(1), Name: "fuzz", Match: P.RuleMatch{Domains: []string{domain}, CIDRs: []string{cidr}, Ports: []P.PortRange{{Start: port, End: port}}}, Action: P.Action{Kind: P.Direct}}}}}
		if c.Validate(nil, nil) != nil {
			return
		}
		m, err := Compile(c)
		if err != nil {
			t.Fatal(err)
		}
		_ = m.Match(Query{Domain: domain, Port: port, Network: "tcp", Resolved: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, P.Action{Kind: P.Reject}, true)
	})
}
