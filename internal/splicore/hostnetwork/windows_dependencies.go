package hostnetwork

import (
	"net/netip"
	"net/url"
	"slices"

	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
)

// WindowsProfileDependencies projects the canonical runtime graph, with no
// protocol-specific routing. A System resolver needs an explicit snapshot of
// its physical DNS endpoints; an unknown underlay fails before resolution.
func WindowsProfileDependencies(state client.ProfileState, systemDNS []netip.Addr) ([]WindowsDependency, error) {
	state = state.Clone()
	bootstrap := "system-dns"
	if state.Network.DNS.Enabled {
		bootstrap = "dns:" + string(state.Network.DNS.BootstrapServer)
	}
	needsBootstrap := func(host string) []string {
		if host == "" {
			return nil
		}
		if _, e := netip.ParseAddr(host); e == nil {
			return nil
		}
		return []string{bootstrap}
	}
	action := func(a P.Action) []string {
		if a.Kind == P.Outbound && a.ID != client.Direct {
			return []string{"outbound:" + string(a.ID)}
		}
		if a.Kind == P.Group {
			return []string{"group:" + string(a.ID)}
		}
		return nil
	}
	active := map[identity.ID]bool{}
	var out []WindowsDependency
	for _, o := range state.Outbounds {
		deps := []string{}
		if o.NodeID != nil {
			active[*o.NodeID] = true
			deps = append(deps, "node:"+string(*o.NodeID))
		}
		out = append(out, WindowsDependency{ID: "outbound:" + string(o.ID), Reason: "outbound", Requires: deps})

	}
	for _, n := range state.Nodes {
		if active[n.ID] {
			out = append(out, WindowsDependency{ID: "node:" + string(n.ID), Reason: "node", Host: n.Endpoint.Host, Requires: needsBootstrap(n.Endpoint.Host)})
		}
	}
	systemNeeded := false
	for _, s := range state.Network.Servers {
		if !state.Network.DNS.Enabled {
			continue
		}
		d := WindowsDependency{ID: "dns:" + string(s.ID), Reason: "dns-upstream", Host: s.Endpoint.Host, Requires: action(s.Detour)}
		if s.ID == state.Network.DNS.BootstrapServer {
			d.Reason = "dns-bootstrap"
		}
		if s.Type == "system" {
			d.Host = ""
			d.Requires = append(d.Requires, "system-dns")
			systemNeeded = true
		} else {
			d.Requires = append(d.Requires, needsBootstrap(d.Host)...)
		}
		out = append(out, d)
	}
	for _, g := range state.Network.Groups {
		d := WindowsDependency{ID: "group:" + string(g.ID), Reason: "group"}
		for _, member := range g.Members {
			d.Requires = append(d.Requires, action(member)...)
		}
		out = append(out, d)
		if probe := g.Probe(); probe != nil {
			u, e := url.Parse(probe.URL)
			if e != nil {
				return nil, identity.Err(identity.Invalid, "invalid health dependency")
			}
			requires := append([]string{d.ID}, needsBootstrap(u.Hostname())...)
			out = append(out, WindowsDependency{ID: "health:" + string(g.ID), Reason: "health", Host: u.Hostname(), Requires: requires})
		}
	}
	for _, i := range state.LocalInbounds {
		if i.Kind != "tun" {
			out = append(out, WindowsDependency{ID: "control:" + string(i.ID), Reason: "control", Host: i.Listen.Host})
		}
	}
	for _, d := range out {
		if slices.Contains(d.Requires, "system-dns") {
			systemNeeded = true
		}
	}
	if systemNeeded {
		if len(systemDNS) == 0 {
			return nil, identity.Err(identity.NotImplemented, "System DNS underlay endpoints must be captured before Windows activation")
		}
		out = append(out, WindowsDependency{ID: "system-dns", Reason: "dns-bootstrap", Addresses: append([]netip.Addr(nil), systemDNS...)})
	}
	return out, ValidateWindowsDependencies(out)
}
