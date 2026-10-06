package hostnetwork

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

type WindowsDependency struct {
	ID        string
	Reason    string
	Host      string
	Addresses []netip.Addr
	Requires  []string
}
type WindowsUnderlay struct {
	InterfaceGUID identity.ID
	Index         uint32
	NextHop       netip.Addr
	Metric        uint32
}
type WindowsRouteState struct {
	Generation    identity.ID `json:"generation"`
	Owner         identity.ID `json:"owner"`
	Destination   string      `json:"destination"`
	InterfaceGUID identity.ID `json:"interface_guid"`
	Index         uint32      `json:"index"`
	NextHop       string      `json:"next_hop"`
	Metric        uint32      `json:"metric"`
	Reasons       []string    `json:"reasons"`
}
type WindowsBypassPlan struct{ Routes []WindowsRouteState }
type WindowsBootstrap func(context.Context, string) ([]netip.Addr, error)

func NormalizeWindowsEndpoint(ip netip.Addr) (netip.Addr, error) {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, identity.Err(identity.Invalid, "invalid bypass endpoint")
	}
	return ip, nil
}
func ValidateWindowsDependencies(dependencies []WindowsDependency) error {
	if len(dependencies) > 1024 {
		return identity.Err(identity.Invalid, "bypass dependency limit exceeded")
	}
	graph := map[string]WindowsDependency{}
	for _, d := range dependencies {
		if !identity.Label(d.ID, 128) || graph[d.ID].ID != "" || len(d.Requires) > 128 || len(d.Addresses) > 32 {
			return identity.Err(identity.Invalid, "invalid bypass dependency")
		}
		switch d.Reason {
		case "node", "dns-bootstrap", "dns-upstream", "health", "control", "outbound", "group", "tun":
		default:
			return identity.Err(identity.Invalid, "unknown bypass reason")
		}
		graph[d.ID] = d
	}
	marks := map[string]uint8{}
	var visit func(string, int) error
	visit = func(id string, depth int) error {
		if depth > 64 || marks[id] == 1 {
			return identity.Err(identity.Invalid, "Windows underlay dependency cycle")
		}
		if marks[id] == 2 {
			return nil
		}
		d, ok := graph[id]
		if !ok {
			return identity.Err(identity.Invalid, "missing bypass dependency")
		}
		marks[id] = 1
		for _, next := range d.Requires {
			if err := visit(next, depth+1); err != nil {
				return err
			}
		}
		marks[id] = 2
		return nil
	}
	for id := range graph {
		if err := visit(id, 0); err != nil {
			return err
		}
	}
	return nil
}
func BuildWindowsBypassPlan(ctx context.Context, dependencies []WindowsDependency, underlays map[bool]WindowsUnderlay, resolve WindowsBootstrap) (WindowsBypassPlan, error) {
	// Validate the complete graph before resolution and before any host write.
	if err := ValidateWindowsDependencies(dependencies); err != nil {
		return WindowsBypassPlan{}, err
	}
	desired := map[netip.Addr][]string{}
	for _, d := range dependencies {
		addresses := append([]netip.Addr(nil), d.Addresses...)
		if d.Host != "" {
			if ip, err := netip.ParseAddr(d.Host); err == nil {
				addresses = append(addresses, ip)
			} else {
				if resolve == nil || len(d.Host) > 253 || strings.ContainsAny(d.Host, "\x00\r\n /\\@") {
					return WindowsBypassPlan{}, identity.Err(identity.Invalid, "invalid bypass hostname")
				}
				ips, err := resolve(ctx, d.Host)
				if err != nil || len(ips) == 0 || len(ips) > 32 {
					return WindowsBypassPlan{}, identity.Err(identity.Unavailable, "bypass bootstrap failed")
				}
				addresses = append(addresses, ips...)
			}
		}
		for _, raw := range addresses {
			ip, err := NormalizeWindowsEndpoint(raw)
			if err != nil {
				return WindowsBypassPlan{}, err
			}
			// OS loopback routes protect local control; never install an underlay
			// route that could move loopback traffic onto a physical interface.
			if ip.IsLoopback() {
				continue
			}
			reason := d.Reason + ":" + d.ID
			if !slices.Contains(desired[ip], reason) {
				desired[ip] = append(desired[ip], reason)
			}
		}
	}
	if len(desired) > 256 {
		return WindowsBypassPlan{}, identity.Err(identity.Invalid, "bypass route limit exceeded")
	}
	plan := WindowsBypassPlan{Routes: []WindowsRouteState{}}
	for ip, reasons := range desired {
		u, ok := underlays[ip.Is4()]
		if !ok || u.InterfaceGUID.Validate() != nil || u.Index == 0 || !u.NextHop.IsValid() || u.NextHop.Zone() != "" || u.NextHop.Is4() != ip.Is4() {
			return WindowsBypassPlan{}, identity.Err(identity.Unavailable, "bypass underlay identity missing")
		}
		slices.Sort(reasons)
		plan.Routes = append(plan.Routes, WindowsRouteState{Destination: netip.PrefixFrom(ip, ip.BitLen()).String(), InterfaceGUID: u.InterfaceGUID, Index: u.Index, NextHop: u.NextHop.String(), Metric: u.Metric, Reasons: reasons})
	}
	slices.SortFunc(plan.Routes, func(a, b WindowsRouteState) int { return strings.Compare(a.Destination, b.Destination) })
	return plan, nil
}
func (r WindowsRouteState) Validate() error {
	p, e := netip.ParsePrefix(r.Destination)
	n, f := netip.ParseAddr(r.NextHop)
	if e != nil || f != nil || p.Masked().String() != r.Destination || p.Addr().Is4In6() || n.Is4In6() || n.Zone() != "" || p.Addr().Is4() != n.Is4() || r.Index == 0 || r.InterfaceGUID.Validate() != nil || r.Generation.Validate() != nil || r.Owner.Validate() != nil || len(r.Reasons) < 1 || len(r.Reasons) > 1024 {
		return identity.Err(identity.Corrupt, "invalid Windows route identity")
	}
	for _, reason := range r.Reasons {
		if !identity.Label(reason, 160) {
			return identity.Err(identity.Corrupt, "invalid Windows route reason")
		}
	}
	return nil
}
func (p WindowsBypassPlan) Records() []Record {
	out := make([]Record, 0, len(p.Routes))
	for _, r := range p.Routes {
		copy := r
		copy.Reasons = append([]string(nil), r.Reasons...)
		out = append(out, Record{Kind: "windows-route", WindowsRoute: &copy})
	}
	return out
}

func sameWindowsRoute(a, b *Record) bool {
	if a == nil || b == nil || a.WindowsRoute == nil || b.WindowsRoute == nil {
		return false
	}
	x, y := *a.WindowsRoute, *b.WindowsRoute
	return x.Destination == y.Destination && x.InterfaceGUID == y.InterfaceGUID && x.Index == y.Index && x.NextHop == y.NextHop && x.Metric == y.Metric
}
