package clientruntime

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

// Reject statically impossible UDP routes/DNS detours. Mixed network defaults
// remain usable for TCP; their UDP admission is checked by network-aware policy.
func validateNetworkCapabilities(state client.ProfileState, registry *registry.Outbounds) error {
	udp := map[identity.ID]bool{client.Direct: true}
	nodes := map[identity.ID]client.RemoteNode{}
	for _, n := range state.Nodes {
		nodes[n.ID] = n
	}
	for _, o := range state.Outbounds {
		if o.NodeID == nil {
			continue
		}
		n := nodes[*o.NodeID]
		f, e := registry.Get(n.Protocol.Protocol, o.Engine)
		if e != nil {
			return e
		}
		enabled := f.Capability().UDP
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(n.Options.Data, &fields)
		if raw, ok := fields["udp"]; ok {
			var v bool
			if json.Unmarshal(raw, &v) != nil {
				return identity.Err(identity.Invalid, "invalid UDP capability")
			}
			enabled = enabled && v
		}
		udp[o.ID] = enabled
	}
	groups := map[identity.ID]P.PolicyGroup{}
	for _, g := range state.Network.Groups {
		groups[g.ID] = g
	}
	var supports func(P.Action, int) bool
	supports = func(a P.Action, depth int) bool {
		if depth > 8 {
			return false
		}
		switch a.Kind {
		case P.Direct, P.Reject:
			return true
		case P.Outbound:
			return udp[a.ID]
		case P.Group:
			g := groups[a.ID]
			if g.Type == "selector" {
				return supports(g.Selector.Selected, depth+1)
			}
			for _, m := range g.Members {
				if supports(m, depth+1) {
					return true
				}
			}
		}
		return false
	}
	for _, r := range state.Network.Route.Rules {
		if len(r.Match.Networks) == 1 && r.Match.Networks[0] == "udp" && !supports(r.Action, 0) {
			return identity.Err(identity.Invalid, "UDP route has no UDP-capable outbound")
		}
	}
	for _, s := range state.Network.Servers {
		if s.Type == "udp" && !supports(s.Detour, 0) {
			return identity.Err(identity.Invalid, "UDP DNS detour has no UDP-capable outbound")
		}
	}
	return nil
}
