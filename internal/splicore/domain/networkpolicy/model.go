// Package networkpolicy owns protocol-independent routing, policy and DNS intent.
package networkpolicy

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"net/netip"
	"net/url"
	"strings"
)

type ActionKind string

const (
	Outbound ActionKind = "outbound"
	Group    ActionKind = "group"
	Direct   ActionKind = "direct"
	Reject   ActionKind = "reject"
)

type Action struct {
	Kind ActionKind  `json:"kind"`
	ID   identity.ID `json:"id,omitempty"`
}

func (a Action) Validate() error {
	switch a.Kind {
	case Direct, Reject:
		if a.ID == "" {
			return nil
		}
	case Outbound:
		if a.ID == "direct" || a.ID.Validate() == nil {
			return nil
		}
	case Group:
		if a.ID.Validate() == nil {
			return nil
		}
	}
	return invalid("invalid route action")
}

type PortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}
type RuleMatch struct {
	SniffedDomains []string      `json:"sniffed_domains,omitempty"`
	Domains        []string      `json:"domains,omitempty"`
	Suffixes       []string      `json:"domain_suffixes,omitempty"`
	Keywords       []string      `json:"domain_keywords,omitempty"`
	CIDRs          []string      `json:"ip_cidrs,omitempty"`
	Ports          []PortRange   `json:"ports,omitempty"`
	Networks       []string      `json:"networks,omitempty"`
	LocalInbounds  []identity.ID `json:"local_inbounds,omitempty"`
	RuleSets       []identity.ID `json:"rule_sets,omitempty"`
}
type RouteRule struct {
	ID     identity.ID `json:"id"`
	Name   string      `json:"name"`
	Match  RuleMatch   `json:"match"`
	Action Action      `json:"action"`
}
type RouteProfile struct {
	Rules []RouteRule `json:"rules"`
	Final *Action     `json:"final,omitempty"`
}
type RuleSet struct {
	ID       identity.ID       `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Rules    []RuleMatch       `json:"rules"`
	Revision identity.Revision `json:"revision"`
	Status   string            `json:"status"`
}
type Probe struct {
	URL             string `json:"url"`
	IntervalSeconds int    `json:"interval_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	ExpectedStatus  int    `json:"expected_status"`
}
type SelectorSettings struct {
	Selected Action `json:"selected"`
}
type URLTestSettings struct {
	Probe       Probe `json:"probe"`
	ToleranceMS int   `json:"tolerance_ms"`
}
type FallbackSettings struct {
	Probe Probe `json:"probe"`
}
type LoadBalanceSettings struct {
	Algorithm string `json:"algorithm"`
	Probe     *Probe `json:"probe,omitempty"`
}
type PolicyGroup struct {
	ID          identity.ID          `json:"id"`
	Name        string               `json:"name"`
	Type        string               `json:"type"`
	Members     []Action             `json:"members"`
	Selector    *SelectorSettings    `json:"selector,omitempty"`
	URLTest     *URLTestSettings     `json:"url_test,omitempty"`
	Fallback    *FallbackSettings    `json:"fallback,omitempty"`
	LoadBalance *LoadBalanceSettings `json:"load_balance,omitempty"`
}

func (g PolicyGroup) Probe() *Probe {
	if g.URLTest != nil {
		return &g.URLTest.Probe
	}
	if g.Fallback != nil {
		return &g.Fallback.Probe
	}
	if g.LoadBalance != nil {
		return g.LoadBalance.Probe
	}
	return nil
}

type DNSServer struct {
	ID       identity.ID      `json:"id"`
	Name     string           `json:"name"`
	Type     string           `json:"type"`
	Endpoint access.Endpoint  `json:"endpoint"`
	Detour   Action           `json:"detour"`
	Strategy string           `json:"strategy"`
	TLS      access.ClientTLS `json:"tls"`
	Path     string           `json:"path,omitempty"`
}
type DNSRule struct {
	ID     identity.ID `json:"id"`
	Name   string      `json:"name"`
	Match  RuleMatch   `json:"match"`
	Server identity.ID `json:"server"`
}
type DNSCachePolicy struct {
	Capacity int `json:"capacity"`
}
type DNSProfile struct {
	Enabled         bool           `json:"enabled"`
	DefaultServer   identity.ID    `json:"default_server,omitempty"`
	BootstrapServer identity.ID    `json:"bootstrap_server,omitempty"`
	Strategy        string         `json:"strategy"`
	Cache           DNSCachePolicy `json:"cache"`
	TimeoutSeconds  int            `json:"timeout_seconds"`
}
type Config struct {
	Route    RouteProfile  `json:"route"`
	RuleSets []RuleSet     `json:"rule_sets"`
	Groups   []PolicyGroup `json:"policy_groups"`
	Servers  []DNSServer   `json:"dns_servers"`
	DNSRules []DNSRule     `json:"dns_rules"`
	DNS      DNSProfile    `json:"dns"`
}

func (c Config) Clone() Config {
	b, _ := json.Marshal(c)
	var copy Config
	_ = json.Unmarshal(b, &copy)
	return copy
}
func Domain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) < 1 || len(s) > 253 || netipMustAddr(s) {
		return "", invalid("invalid domain rule")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", invalid("invalid domain rule")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", invalid("invalid domain rule")
			}
		}
	}
	return s, nil
}
func netipMustAddr(s string) bool { _, err := netip.ParseAddr(s); return err == nil }
func Strategy(s string) bool {
	return s == "" || s == "dual" || s == "ipv4_only" || s == "ipv6_only" || s == "prefer_ipv4" || s == "prefer_ipv6"
}
func invalid(message string) error { return identity.Err(identity.Invalid, message) }
func label(id identity.ID, name string) error {
	if id.Validate() != nil || !identity.Label(name, 128) {
		return invalid("invalid network resource identity")
	}
	return nil
}
func (p Probe) Validate() error {
	u, err := url.Parse(p.URL)
	if err != nil || len(p.URL) > 2048 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || p.IntervalSeconds < 1 || p.IntervalSeconds > 86400 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 10 || p.ExpectedStatus < 100 || p.ExpectedStatus > 599 {
		return invalid("invalid HTTP health probe")
	}
	if u.Port() != "" {
		if _, err = netip.ParseAddrPort("127.0.0.1:" + u.Port()); err != nil || u.Port() == "0" {
			return invalid("invalid probe port")
		}
	}
	if !netipMustAddr(u.Hostname()) {
		if _, err = Domain(u.Hostname()); err != nil {
			return err
		}
	}
	return nil
}
func (c Config) Validate(out, in map[identity.ID]bool) error {
	if document, err := json.Marshal(c); err != nil || len(document) > 2<<20 {
		return invalid("canonical network configuration exceeds document limit")
	}
	if len(c.Route.Rules) > 10000 || len(c.RuleSets) > 128 || len(c.Groups) > 64 || len(c.Servers) > 32 || len(c.DNSRules) > 256 {
		return invalid("network configuration exceeds limits")
	}
	sets := map[identity.ID]RuleSet{}
	groups := map[identity.ID]PolicyGroup{}
	servers := map[identity.ID]DNSServer{}
	total := len(c.Route.Rules)
	for _, s := range c.RuleSets {
		if label(s.ID, s.Name) != nil || sets[s.ID].ID != "" || s.Revision < 1 || (s.Type != "inline" && s.Type != "local") || (s.Status != "enabled" && s.Status != "disabled") || len(s.Rules) == 0 {
			return invalid("invalid ruleset")
		}
		sets[s.ID] = s
		total += len(s.Rules)
	}
	if total > 20000 {
		return invalid("ruleset compilation exceeds limits")
	}
	for _, g := range c.Groups {
		if label(g.ID, g.Name) != nil || groups[g.ID].ID != "" || len(g.Members) < 1 || len(g.Members) > 129 {
			return invalid("invalid policy group")
		}
		groups[g.ID] = g
	}
	action := func(a Action) error {
		if a.Validate() != nil {
			return invalid("invalid action")
		}
		if a.Kind == Outbound && !out[a.ID] || a.Kind == Group && groups[a.ID].ID == "" {
			return invalid("action references missing outbound or group")
		}
		return nil
	}
	var match func(RuleMatch, bool) error
	match = func(m RuleMatch, dnsOnly bool) error {
		size := len(m.SniffedDomains) + len(m.Domains) + len(m.Suffixes) + len(m.Keywords) + len(m.CIDRs) + len(m.Ports) + len(m.LocalInbounds) + len(m.RuleSets)
		if size > 256 || len(m.Networks) > 2 {
			return invalid("rule match exceeds limits")
		}
		for _, s := range append(append([]string{}, m.Domains...), m.Suffixes...) {
			if _, e := Domain(s); e != nil {
				return e
			}
		}
		for _, s := range m.SniffedDomains {
			if _, e := Domain(s); e != nil {
				return e
			}
		}
		for _, s := range m.Keywords {
			if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " \t\r\n/*\\") {
				return invalid("invalid domain keyword")
			}
		}
		for _, s := range m.CIDRs {
			if p, e := netip.ParsePrefix(s); e != nil || p != p.Masked() {
				return invalid("invalid or noncanonical CIDR")
			}
		}
		for _, p := range m.Ports {
			if p.Start == 0 || p.End == 0 || p.Start > p.End {
				return invalid("invalid destination port range")
			}
		}
		for _, s := range m.Networks {
			if s != "tcp" && s != "udp" {
				return invalid("invalid route network")
			}
		}
		for _, id := range m.LocalInbounds {
			if !in[id] {
				return invalid("missing local inbound")
			}
		}
		for _, id := range m.RuleSets {
			if sets[id].ID == "" {
				return invalid("missing ruleset")
			}
		}
		if dnsOnly && (len(m.SniffedDomains)+len(m.CIDRs)+len(m.Ports)+len(m.Networks)+len(m.LocalInbounds) > 0) {
			return invalid("DNS rules require domain-only matches")
		}
		return nil
	}
	ids := map[identity.ID]bool{}
	for _, r := range c.Route.Rules {
		if label(r.ID, r.Name) != nil || ids[r.ID] {
			return invalid("invalid route rule")
		}
		ids[r.ID] = true
		if err := match(r.Match, false); err != nil {
			return err
		}
		if err := action(r.Action); err != nil {
			return err
		}
	}
	if c.Route.Final != nil {
		if err := action(*c.Route.Final); err != nil {
			return err
		}
	}
	for _, s := range c.RuleSets {
		for _, m := range s.Rules {
			if err := match(m, false); err != nil {
				return err
			}
		}
	}
	setGraph := map[identity.ID][]identity.ID{}
	for id, s := range sets {
		setGraph[id] = nil
		for _, m := range s.Rules {
			setGraph[id] = append(setGraph[id], m.RuleSets...)
		}
	}
	if err := acyclic(setGraph, 16); err != nil {
		return err
	}
	dnsChecked := map[identity.ID]bool{}
	var dnsSet func(identity.ID) error
	dnsSet = func(id identity.ID) error {
		if dnsChecked[id] {
			return nil
		}
		dnsChecked[id] = true
		for _, m := range sets[id].Rules {
			if err := match(m, true); err != nil {
				return err
			}
			for _, ref := range m.RuleSets {
				if err := dnsSet(ref); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, g := range c.Groups {
		count := 0
		for _, v := range []bool{g.Selector != nil, g.URLTest != nil, g.Fallback != nil, g.LoadBalance != nil} {
			if v {
				count++
			}
		}
		if count != 1 {
			return invalid("group requires exactly one typed strategy")
		}
		seen := map[Action]bool{}
		for _, a := range g.Members {
			if seen[a] {
				return invalid("duplicate group member")
			}
			seen[a] = true
			if err := action(a); err != nil {
				return err
			}
		}
		switch g.Type {
		case "selector":
			if g.Selector == nil || !seen[g.Selector.Selected] {
				return invalid("empty or invalid selector")
			}
		case "url_test":
			if g.URLTest == nil || g.URLTest.ToleranceMS < 0 || g.URLTest.ToleranceMS > 60000 {
				return invalid("invalid URL-Test strategy")
			}
		case "fallback":
			if g.Fallback == nil {
				return invalid("invalid fallback strategy")
			}
		case "load_balance":
			if g.LoadBalance == nil || g.LoadBalance.Algorithm != "round_robin" {
				return invalid("unsupported load-balance algorithm")
			}
		default:
			return invalid("unsupported policy strategy")
		}
		if p := g.Probe(); p != nil {
			if err := p.Validate(); err != nil {
				return err
			}
		}
	}
	groupGraph := map[identity.ID][]identity.ID{}
	probes := 0
	for id, g := range groups {
		groupGraph[id] = nil
		for _, a := range g.Members {
			if a.Kind == Group {
				groupGraph[id] = append(groupGraph[id], a.ID)
			}
		}
		if g.Probe() != nil {
			probes += len(g.Members)
		}
	}
	if probes > 256 {
		return invalid("health scheduler exceeds membership limit")
	}
	if err := acyclic(groupGraph, 8); err != nil {
		return err
	}
	for _, s := range c.Servers {
		if label(s.ID, s.Name) != nil || servers[s.ID].ID != "" || !Strategy(s.Strategy) {
			return invalid("invalid DNS server")
		}
		servers[s.ID] = s
		if err := action(s.Detour); err != nil {
			return err
		}
		if s.Detour.Kind == Reject {
			return invalid("DNS server cannot use REJECT")
		}
		switch s.Type {
		case "doh":
			return invalid("DoH deferred: inherited transport lacks bounded response allocation")
		case "system":
			if s.Detour.Kind != Direct || s.Endpoint.Host != "" || s.Endpoint.Port != 0 || s.Path != "" || s.TLS.Validate("none") != nil {
				return invalid("system resolver requires explicit DIRECT")
			}
		case "udp", "tcp":
			if s.Endpoint.Validate() != nil || s.Path != "" || s.TLS.Validate("none") != nil {
				return invalid("invalid plain DNS endpoint")
			}
		case "dot":
			if s.Endpoint.Validate() != nil || s.TLS.Validate("tls") != nil {
				return invalid("invalid verified TLS DNS endpoint")
			}
			if s.Type == "dot" && s.Path != "" || s.Type == "doh" && (!strings.HasPrefix(s.Path, "/") || len(s.Path) > 512 || strings.ContainsAny(s.Path, "\r\n?#")) {
				return invalid("invalid DoH path")
			}
		default:
			return invalid("unsupported DNS transport")
		}
	}
	ids = map[identity.ID]bool{}
	for _, r := range c.DNSRules {
		if label(r.ID, r.Name) != nil || ids[r.ID] || servers[r.Server].ID == "" {
			return invalid("invalid DNS rule reference")
		}
		ids[r.ID] = true
		if err := match(r.Match, true); err != nil {
			return err
		}
		for _, ref := range r.Match.RuleSets {
			if err := dnsSet(ref); err != nil {
				return err
			}
		}
	}
	if !Strategy(c.DNS.Strategy) || c.DNS.Cache.Capacity < 0 || c.DNS.Cache.Capacity > 4096 || c.DNS.TimeoutSeconds < 0 || c.DNS.TimeoutSeconds > 10 || c.DNS.DefaultServer != "" && servers[c.DNS.DefaultServer].ID == "" || c.DNS.BootstrapServer != "" && servers[c.DNS.BootstrapServer].ID == "" {
		return invalid("invalid DNS strategy")
	}
	if c.DNS.Enabled {
		if servers[c.DNS.DefaultServer].ID == "" || servers[c.DNS.BootstrapServer].ID == "" || c.DNS.Cache.Capacity < 0 || c.DNS.Cache.Capacity > 4096 || c.DNS.TimeoutSeconds < 1 || c.DNS.TimeoutSeconds > 10 {
			return invalid("invalid DNS profile")
		}
		bootstrap := servers[c.DNS.BootstrapServer]
		if bootstrap.Detour.Kind != Direct || (bootstrap.Type != "system" && ((bootstrap.Type != "udp" && bootstrap.Type != "tcp") || !netipMustAddr(bootstrap.Endpoint.Host))) {
			return invalid("DNS bootstrap dependency loop: requires system or IP-only DIRECT UDP/TCP resolver")
		}
	}
	return nil
}

// O(vertices+edges), including shared DAG subgraphs; no exponential recursive validation.
func acyclic(graph map[identity.ID][]identity.ID, limit int) error {
	colors := map[identity.ID]uint8{}
	heights := map[identity.ID]int{}
	var visit func(identity.ID) (int, error)
	visit = func(id identity.ID) (int, error) {
		if colors[id] == 1 {
			return 0, invalid("network dependency cycle")
		}
		if colors[id] == 2 {
			return heights[id], nil
		}
		colors[id] = 1
		height := 0
		for _, child := range graph[id] {
			h, err := visit(child)
			if err != nil {
				return 0, err
			}
			height = max(height, h+1)
		}
		if height > limit {
			return 0, invalid("network dependency depth exceeded")
		}
		colors[id] = 2
		heights[id] = height
		return height, nil
	}
	for id := range graph {
		if _, err := visit(id); err != nil {
			return err
		}
	}
	return nil
}
