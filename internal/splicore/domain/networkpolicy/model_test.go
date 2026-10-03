package networkpolicy

import (
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	"testing"
)

func id(n int) identity.ID { return identity.ID(fmt.Sprintf("00000000-0000-4000-8000-%012d", n)) }
func valid() Config {
	a := Action{Kind: Outbound, ID: id(1)}
	return Config{
		Route:   RouteProfile{Rules: []RouteRule{{ID: id(2), Name: "route", Match: RuleMatch{Suffixes: []string{"synthetic.test"}}, Action: Action{Kind: Group, ID: id(3)}}}},
		Groups:  []PolicyGroup{{ID: id(3), Name: "selector", Type: "selector", Members: []Action{a}, Selector: &SelectorSettings{Selected: a}}},
		Servers: []DNSServer{{ID: id(4), Name: "bootstrap", Type: "udp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 53}, Detour: Action{Kind: Direct}}},
		DNS:     DNSProfile{Enabled: true, DefaultServer: id(4), BootstrapServer: id(4), TimeoutSeconds: 2, Cache: DNSCachePolicy{Capacity: 16}},
	}
}
func TestCanonicalValidationAndOwnership(t *testing.T) {
	c := valid()
	out := map[identity.ID]bool{id(1): true}
	if err := c.Validate(out, nil); err != nil {
		t.Fatal(err)
	}
	copy := c.Clone()
	copy.Route.Rules[0].Match.Suffixes[0] = "changed.test"
	copy.Groups[0].Selector.Selected = Action{Kind: Direct}
	if c.Route.Rules[0].Match.Suffixes[0] != "synthetic.test" || c.Groups[0].Selector.Selected.Kind != Outbound {
		t.Fatal("clone shares mutable state")
	}
	cases := map[string]func(*Config){
		"invalid domain":     func(c *Config) { c.Route.Rules[0].Match.Domains = []string{"bad..test"} },
		"invalid keyword":    func(c *Config) { c.Route.Rules[0].Match.Keywords = []string{""} },
		"invalid CIDR":       func(c *Config) { c.Route.Rules[0].Match.CIDRs = []string{"127.0.0.1/8"} },
		"invalid IPv6 CIDR":  func(c *Config) { c.Route.Rules[0].Match.CIDRs = []string{"::1/129"} },
		"invalid port":       func(c *Config) { c.Route.Rules[0].Match.Ports = []PortRange{{Start: 0, End: 80}} },
		"reversed ports":     func(c *Config) { c.Route.Rules[0].Match.Ports = []PortRange{{Start: 90, End: 80}} },
		"missing outbound":   func(c *Config) { c.Groups[0].Members[0].ID = id(999) },
		"missing group":      func(c *Config) { c.Route.Rules[0].Action.ID = id(999) },
		"missing ruleset":    func(c *Config) { c.Route.Rules[0].Match.RuleSets = []identity.ID{id(999)} },
		"empty selector":     func(c *Config) { c.Groups[0].Selector = nil },
		"two strategies":     func(c *Config) { c.Groups[0].Fallback = &FallbackSettings{} },
		"invalid network":    func(c *Config) { c.Route.Rules[0].Match.Networks = []string{"quic"} },
		"missing local":      func(c *Config) { c.Route.Rules[0].Match.LocalInbounds = []identity.ID{id(999)} },
		"DNS endpoint":       func(c *Config) { c.Servers[0].Endpoint.Port = 0 },
		"DNS loop via proxy": func(c *Config) { c.Servers[0].Detour = Action{Kind: Outbound, ID: id(1)} },
		"DNS loop hostname":  func(c *Config) { c.Servers[0].Endpoint.Host = "resolver.synthetic.test" },
		"missing DNS":        func(c *Config) { c.DNS.DefaultServer = id(999) },
		"DoH deferred":       func(c *Config) { c.Servers[0].Type = "doh" },
		"bad URL": func(c *Config) {
			c.Groups[0].Type = "fallback"
			c.Groups[0].Selector = nil
			c.Groups[0].Fallback = &FallbackSettings{Probe: Probe{URL: "file:///etc/hosts", IntervalSeconds: 1, TimeoutSeconds: 1, ExpectedStatus: 200}}
		},
		"direct cycle": func(c *Config) {
			a := Action{Kind: Group, ID: id(3)}
			c.Groups[0].Members = []Action{a}
			c.Groups[0].Selector.Selected = a
		},
		"indirect cycle": func(c *Config) {
			a := Action{Kind: Group, ID: id(5)}
			c.Groups[0].Members = []Action{a}
			c.Groups[0].Selector.Selected = a
			b := Action{Kind: Group, ID: id(3)}
			c.Groups = append(c.Groups, PolicyGroup{ID: id(5), Name: "nested", Type: "selector", Members: []Action{b}, Selector: &SelectorSettings{Selected: b}})
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := c.Clone()
			change(&bad)
			if err := bad.Validate(out, nil); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, domain := range []string{"UPPER.Synthetic.Test.", "localhost", "xn--bcher-kva.test"} {
		if _, err := Domain(domain); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRuleSetGraphCyclesAndSharedDAG(t *testing.T) {
	c := Config{}
	for n := 1; n <= 16; n++ {
		s := RuleSet{ID: id(n), Name: "set", Type: "inline", Status: "enabled", Revision: 1}
		if n == 16 {
			s.Rules = []RuleMatch{{Domains: []string{"leaf.test"}}}
		} else {
			for i := n + 1; i <= 16; i++ {
				s.Rules = append(s.Rules, RuleMatch{RuleSets: []identity.ID{id(i)}})
			}
		}
		c.RuleSets = append(c.RuleSets, s)
	}
	if err := c.Validate(nil, nil); err != nil {
		t.Fatal(err)
	}
	c.RuleSets[15].Rules = []RuleMatch{{RuleSets: []identity.ID{id(1)}}}
	if err := c.Validate(nil, nil); err == nil {
		t.Fatal("ruleset cycle admitted")
	}
}

func FuzzCanonicalNetwork(f *testing.F) {
	b, _ := json.Marshal(valid())
	f.Add(b)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var c Config
		if jsonstrict.DecodeLimit(b, &c, 2<<20) == nil {
			_ = c.Validate(map[identity.ID]bool{id(1): true}, nil)
		}
	})
}
