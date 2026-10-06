package hostnetwork

import (
	"context"
	"net"
	"net/netip"
	"slices"

	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

type Plan struct {
	Records []Record
	Bypass  []string
	Egress  string
}

func (p *Platform) Plan(ctx context.Context, t client.TUNSettings, endpoints []netip.Addr) (Plan, error) {
	if err := t.Validate(); err != nil {
		return Plan{}, err
	}
	if _, err := net.InterfaceByName(t.Interface); err == nil {
		return Plan{}, identity.Err(identity.Conflict, "TUN interface already exists")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return Plan{}, identity.Err(identity.Unavailable, "host interface snapshot failed")
	}
	bypass := append([]string(nil), t.Exclude...)
	configured := []netip.Prefix{}
	for _, raw := range t.Addresses {
		configured = append(configured, netip.MustParsePrefix(raw))
	}
	for _, i := range interfaces {
		addresses, e := i.Addrs()
		if e != nil {
			return Plan{}, identity.Err(identity.Unavailable, "host address snapshot failed")
		}
		for _, a := range addresses {
			prefix, e := netip.ParsePrefix(a.String())
			if e != nil {
				continue
			}
			for _, candidate := range configured {
				if candidate.Overlaps(prefix) {
					return Plan{}, identity.Err(identity.Conflict, "TUN address range collides with an existing interface")
				}
			}
			bypass = append(bypass, prefix.Masked().String())
		}
	}
	for _, ip := range endpoints {
		// net.Resolver may represent an IPv4 result as IPv4-mapped IPv6.
		// Linux rejects a mapped prefix as an IPv6 route; plan its real family.
		ip = ip.Unmap()
		if ip.IsValid() {
			bypass = append(bypass, netip.PrefixFrom(ip, ip.BitLen()).String())
		}
	}
	bypass = append(bypass, "127.0.0.0/8", "224.0.0.0/4", "169.254.0.0/16", "::1/128", "fe80::/10", "ff00::/8")
	families := map[bool]bool{}
	for _, a := range configured {
		families[a.Addr().Is4()] = true
	}
	filtered := []string{}
	for _, raw := range bypass {
		prefix, e := netip.ParsePrefix(raw)
		if e != nil {
			return Plan{}, e
		}
		if families[prefix.Addr().Is4()] && !slices.Contains(filtered, raw) {
			filtered = append(filtered, raw)
		}
	}
	slices.Sort(filtered)
	plan := Plan{Records: []Record{{Kind: "interface", Interface: t.Interface, Addresses: append([]string(nil), t.Addresses...), MTU: t.MTU}}, Bypass: filtered}
	for _, raw := range t.Addresses {
		plan.Records = append(plan.Records, Record{Kind: "address", Interface: t.Interface, Prefix: raw})
	}
	if t.AutoRoute {
		if err = p.capturePlan(ctx, t, &plan); err != nil {
			return Plan{}, err
		}
	}
	return plan, nil
}
func ProxyPlan(endpoint string) []Record {
	values := map[string]ProxyValue{"ProxyEnable": {Present: true, Type: 4, Number: 1}, "ProxyServer": {Present: true, Type: 1, Text: endpoint}, "ProxyOverride": {Present: true, Type: 1, Text: "<local>"}, "AutoConfigURL": {Present: false}, "AutoDetect": {Present: true, Type: 4, Number: 0}}
	out := []Record{}
	for _, key := range []string{"ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect", "ProxyEnable"} {
		out = append(out, Record{Kind: "proxy", Proxy: &ProxyState{Values: map[string]ProxyValue{key: values[key]}}})
	}
	return out
}
