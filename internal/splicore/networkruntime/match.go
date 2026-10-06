// Package networkruntime compiles canonical routing/DNS/policy into owned artifacts.
package networkruntime

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"net/netip"
	"strings"
	"sync/atomic"
)

type Query struct {
	Domain       string       `json:"domain,omitempty"`
	IP           netip.Addr   `json:"ip,omitzero"`
	Resolved     []netip.Addr `json:"resolved_ips,omitempty"`
	Port         uint16       `json:"port"`
	Network      string       `json:"network"`
	LocalInbound identity.ID  `json:"local_inbound,omitempty"`
}

func (q Query) Validate() error {
	if q.Port == 0 || (q.Network != "tcp" && q.Network != "udp") || q.Domain == "" && !q.IP.IsValid() || len(q.Resolved) > 32 {
		return identity.Err(identity.Invalid, "invalid route query")
	}
	if q.Domain != "" {
		if _, err := P.Domain(q.Domain); err != nil {
			return err
		}
	}
	if q.LocalInbound != "" && q.LocalInbound.Validate() != nil {
		return identity.Err(identity.Invalid, "invalid local inbound query")
	}
	for _, ip := range q.Resolved {
		if !ip.IsValid() {
			return identity.Err(identity.Invalid, "invalid resolved IP")
		}
	}
	return nil
}

type compiledMatch struct {
	exact           map[string]bool
	suffix, keyword []string
	cidrs           []netip.Prefix
	ports           []P.PortRange
	networks        map[string]bool
	locals          map[identity.ID]bool
	sets            []identity.ID
}
type compiledRule struct {
	id     identity.ID
	match  compiledMatch
	action P.Action
	hits   atomic.Int64
}
type compiledSet struct {
	enabled bool
	rules   []compiledMatch
}
type Matcher struct {
	rules []*compiledRule
	sets  map[identity.ID]compiledSet
	dns   []struct {
		match  compiledMatch
		server identity.ID
	}
}

func compileMatch(m P.RuleMatch) (compiledMatch, error) {
	c := compiledMatch{exact: map[string]bool{}, networks: map[string]bool{}, locals: map[identity.ID]bool{}, ports: append([]P.PortRange(nil), m.Ports...), sets: append([]identity.ID(nil), m.RuleSets...)}
	for _, s := range m.Domains {
		d, err := P.Domain(s)
		if err != nil {
			return c, err
		}
		c.exact[d] = true
	}
	for _, s := range m.Suffixes {
		d, err := P.Domain(s)
		if err != nil {
			return c, err
		}
		c.suffix = append(c.suffix, d)
	}
	for _, s := range m.Keywords {
		c.keyword = append(c.keyword, strings.ToLower(s))
	}
	for _, s := range m.CIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return c, identity.Err(identity.Invalid, "invalid CIDR")
		}
		c.cidrs = append(c.cidrs, p)
	}
	for _, n := range m.Networks {
		c.networks[n] = true
	}
	for _, id := range m.LocalInbounds {
		c.locals[id] = true
	}
	return c, nil
}
func Compile(c P.Config) (*Matcher, error) {
	m := &Matcher{sets: map[identity.ID]compiledSet{}}
	for _, r := range c.Route.Rules {
		match, err := compileMatch(r.Match)
		if err != nil {
			return nil, err
		}
		m.rules = append(m.rules, &compiledRule{id: r.ID, match: match, action: r.Action})
	}
	for _, s := range c.RuleSets {
		set := compiledSet{enabled: s.Status == "enabled"}
		for _, r := range s.Rules {
			match, err := compileMatch(r)
			if err != nil {
				return nil, err
			}
			set.rules = append(set.rules, match)
		}
		m.sets[s.ID] = set
	}
	for _, r := range c.DNSRules {
		match, err := compileMatch(r.Match)
		if err != nil {
			return nil, err
		}
		m.dns = append(m.dns, struct {
			match  compiledMatch
			server identity.ID
		}{match, r.Server})
	}
	return m, nil
}

type setResult struct {
	matched bool
	used    []identity.ID
}

func (m *Matcher) matches(c compiledMatch, q Query, depth int, used *[]identity.ID, memo map[identity.ID]setResult) bool {
	if depth > 16 {
		return false
	}
	domain := strings.ToLower(strings.TrimSuffix(q.Domain, "."))
	if len(c.exact)+len(c.suffix)+len(c.keyword) > 0 {
		ok := c.exact[domain]
		for _, s := range c.suffix {
			ok = ok || domain == s || strings.HasSuffix(domain, "."+s)
		}
		for _, s := range c.keyword {
			ok = ok || strings.Contains(domain, s)
		}
		if !ok {
			return false
		}
	}
	if len(c.cidrs) > 0 {
		ok := false
		for _, p := range c.cidrs {
			ok = ok || p.Contains(q.IP)
			for _, ip := range q.Resolved {
				ok = ok || p.Contains(ip)
			}
		}
		if !ok {
			return false
		}
	}
	if len(c.ports) > 0 {
		ok := false
		for _, p := range c.ports {
			ok = ok || q.Port >= p.Start && q.Port <= p.End
		}
		if !ok {
			return false
		}
	}
	if len(c.networks) > 0 && !c.networks[q.Network] || len(c.locals) > 0 && !c.locals[q.LocalInbound] {
		return false
	}
	if len(c.sets) > 0 {
		for _, id := range c.sets {
			result, done := memo[id]
			if done {
				if result.matched {
					if used != nil {
						*used = append(*used, result.used...)
					}
					return true
				}
				continue
			}
			s := m.sets[id]
			if !s.enabled {
				continue
			}
			for _, r := range s.rules {
				var nested []identity.ID
				if m.matches(r, q, depth+1, &nested, memo) {
					memo[id] = setResult{true, append([]identity.ID{id}, nested...)}
					if used != nil {
						*used = append(*used, id)
						*used = append(*used, nested...)
					}
					return true
				}
			}
			memo[id] = setResult{}
		}
		return false
	}
	return true
}

type Explanation struct {
	Rule      identity.ID   `json:"matched_rule,omitempty"`
	RuleSets  []identity.ID `json:"rule_sets"`
	Action    P.Action      `json:"action"`
	Group     identity.ID   `json:"policy_group,omitempty"`
	Selected  P.Action      `json:"selected"`
	Available bool          `json:"available"`
}

func (m *Matcher) Match(q Query, fallback P.Action, count bool) Explanation {
	e := Explanation{Action: fallback, RuleSets: []identity.ID{}}
	memo := map[identity.ID]setResult{}
	for _, r := range m.rules {
		var sets []identity.ID
		if m.matches(r.match, q, 0, &sets, memo) {
			e.Rule = r.id
			e.Action = r.action
			e.RuleSets = append(e.RuleSets, sets...)
			if count {
				r.hits.Add(1)
			}
			break
		}
	}
	return e
}
func (m *Matcher) DNSServer(domain string, fallback identity.ID) identity.ID {
	q := Query{Domain: domain}
	memo := map[identity.ID]setResult{}
	for _, r := range m.dns {
		if m.matches(r.match, q, 0, nil, memo) {
			return r.server
		}
	}
	return fallback
}

type RuleHits struct {
	ID   identity.ID `json:"id"`
	Hits int64       `json:"hits,string"`
}

func (m *Matcher) Hits() []RuleHits {
	out := []RuleHits{}
	for _, r := range m.rules {
		out = append(out, RuleHits{r.id, r.hits.Load()})
	}
	return out
}
