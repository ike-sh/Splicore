package client

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
)

// ValidateProviderDependencies checks every possible group member, not only the
// presently selected member. Provider fetch cannot bootstrap from its own feed.
func (s ProfileState) ValidateProviderDependencies() error {
	nodes := map[identity.ID]RemoteNode{}
	out := map[identity.ID]Outbound{}
	groups := map[identity.ID]P.PolicyGroup{}
	for _, n := range s.Nodes {
		nodes[n.ID] = n
	}
	for _, o := range s.Outbounds {
		out[o.ID] = o
	}
	for _, g := range s.Network.Groups {
		groups[g.ID] = g
	}
	edges := map[identity.ID][]identity.ID{}
	var deps func(P.Action, int) ([]identity.ID, error)
	deps = func(a P.Action, depth int) ([]identity.ID, error) {
		if depth > 8 {
			return nil, invalid()
		}
		switch a.Kind {
		case P.Direct:
			return nil, nil
		case P.Outbound:
			o, ok := out[a.ID]
			if !ok {
				return nil, invalid()
			}
			if o.NodeID == nil {
				return nil, nil
			}
			p := nodes[*o.NodeID].Provenance.ProviderID
			if p != "" {
				return []identity.ID{p}, nil
			}
			return nil, nil
		case P.Group:
			g, ok := groups[a.ID]
			if !ok {
				return nil, invalid()
			}
			var all []identity.ID
			for _, m := range g.Members {
				d, e := deps(m, depth+1)
				if e != nil {
					return nil, e
				}
				all = append(all, d...)
			}
			return all, nil
		default:
			return nil, invalid()
		}
	}
	for _, p := range s.Management.Providers {
		d, e := deps(p.FetchAction, 0)
		if e != nil {
			return e
		}
		edges[p.ID] = d
	}
	visiting := map[identity.ID]bool{}
	done := map[identity.ID]bool{}
	var visit func(identity.ID) error
	visit = func(id identity.ID) error {
		if visiting[id] {
			return identity.Err(identity.Invalid, "provider bootstrap dependency cycle")
		}
		if done[id] {
			return nil
		}
		visiting[id] = true
		for _, next := range edges[id] {
			if e := visit(next); e != nil {
				return e
			}
		}
		delete(visiting, id)
		done[id] = true
		return nil
	}
	for id := range edges {
		if e := visit(id); e != nil {
			return e
		}
	}
	return nil
}
