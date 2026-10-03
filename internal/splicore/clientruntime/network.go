package clientruntime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/networkruntime"
	"net/netip"
)

func bootstrapKey(c P.Config, n client.RemoteNode) string {
	if !c.DNS.Enabled || n.ID == "" {
		return ""
	}
	if _, err := netip.ParseAddr(n.Endpoint.Host); err == nil {
		return ""
	}
	var server P.DNSServer
	for _, s := range c.Servers {
		if s.ID == c.DNS.BootstrapServer {
			server = s
		}
	}
	b, _ := json.Marshal(struct {
		Server   P.DNSServer
		Strategy string
		Timeout  int
	}{server, c.DNS.Strategy, c.DNS.TimeoutSeconds})
	return string(b)
}
func selectedOutbound(a P.Action) identity.ID {
	if a.Kind == P.Direct {
		return client.Direct
	}
	return a.ID
}
func routeFallback(gen *snapshot, inbound identity.ID) P.Action {
	for _, i := range gen.state.LocalInbounds {
		if i.ID == inbound && i.SelectedOutbound != "" {
			return P.Action{Kind: P.Outbound, ID: i.SelectedOutbound}
		}
	}
	if gen.state.Network.Route.Final != nil {
		return *gen.state.Network.Route.Final
	}
	return P.Action{Kind: P.Outbound, ID: gen.state.Route.DefaultOutbound}
}
func selectRoute(ctx context.Context, gen *snapshot, inbound identity.ID, target access.Endpoint, network string, affinity map[identity.ID]P.Action) (networkruntime.Explanation, access.Endpoint, error) {
	q := networkruntime.Query{Port: target.Port, Network: network, LocalInbound: inbound}
	ip, err := netip.ParseAddr(target.Host)
	if err == nil {
		q.IP = ip
	} else {
		q.Domain = target.Host
	}
	if err := q.Validate(); err != nil {
		return networkruntime.Explanation{}, target, err
	}
	// A first unconditional domain REJECT does not perform a DNS query.
	initial := gen.network.Matcher.Match(q, routeFallback(gen, inbound), false)
	if initial.Action.Kind == P.Reject && len(gen.state.Network.Route.Rules) > 0 && initial.Rule == gen.state.Network.Route.Rules[0].ID {
		selected, err := gen.network.Explain(q, routeFallback(gen, inbound), true, affinity)
		return selected, target, err
	}
	if q.Domain != "" && gen.state.Network.DNS.Enabled {
		result, err := gen.network.Lookup(ctx, q.Domain)
		if err != nil {
			return networkruntime.Explanation{}, target, err
		}
		if len(result.Addresses) == 0 {
			return networkruntime.Explanation{}, target, identity.Err(identity.Unavailable, "DNS has no usable address")
		}
		// Match the address that this connection will actually dial. Original domain remains available.
		q.Resolved = result.Addresses[:1]
		target.Host = result.Addresses[0].String()
	}
	selected, err := gen.network.Explain(q, routeFallback(gen, inbound), true, affinity)
	return selected, target, err
}

type NetworkStatus struct {
	Rules  []networkruntime.RuleHits    `json:"rules"`
	Groups []networkruntime.GroupStatus `json:"groups"`
	DNS    networkruntime.DNSStats      `json:"dns"`
}

func (m *Manager) NetworkStatus() NetworkStatus {
	gen := m.acquire()
	if gen == nil {
		return NetworkStatus{Rules: []networkruntime.RuleHits{}, Groups: []networkruntime.GroupStatus{}}
	}
	defer gen.release()
	return NetworkStatus{gen.network.Matcher.Hits(), gen.network.Groups(), gen.network.DNSStats()}
}
func (m *Manager) ExplainRoute(q networkruntime.Query) (networkruntime.Explanation, error) {
	gen := m.acquire()
	if gen == nil {
		return networkruntime.Explanation{}, identity.Err(identity.Unavailable, "client runtime unavailable")
	}
	defer gen.release()
	explanation, err := gen.network.Explain(q, routeFallback(gen, q.LocalInbound), false, nil)
	var failure *identity.Error
	if errors.As(err, &failure) && failure.Code == identity.Unavailable {
		// Dry run still explains the matched rule/group when no member is available.
		return explanation, nil
	}
	return explanation, err
}
func (m *Manager) DNSLookup(ctx context.Context, domain string) (networkruntime.DNSResult, error) {
	gen := m.acquire()
	if gen == nil || !gen.state.Enabled {
		if gen != nil {
			gen.release()
		}
		return networkruntime.DNSResult{}, identity.Err(identity.Unavailable, "client runtime stopped")
	}
	defer gen.release()
	return gen.network.Lookup(ctx, domain)
}
func (m *Manager) FlushDNS() error {
	gen := m.acquire()
	if gen == nil {
		return identity.Err(identity.Unavailable, "client runtime unavailable")
	}
	defer gen.release()
	gen.network.FlushCache()
	return nil
}
