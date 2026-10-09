package client

import (
	"net/netip"
	"regexp"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

// TUNSettings is Splicore intent, independent of upstream runtime JSON.
type TUNSettings struct {
	Interface string   `json:"interface"`
	Addresses []string `json:"addresses"`
	MTU       uint32   `json:"mtu"`
	AutoRoute bool     `json:"auto_route"`
	Include   []string `json:"include,omitempty"`
	Exclude   []string `json:"exclude,omitempty"`
	DNSHijack bool     `json:"dns_hijack"`
	Stack     string   `json:"stack,omitempty"`
}

var interfaceLabel = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)

func (t TUNSettings) Validate() error {
	if !interfaceLabel.MatchString(t.Interface) || t.MTU < 1280 || t.MTU > 9000 || len(t.Addresses) < 1 || len(t.Addresses) > 2 || len(t.Include) > 128 || len(t.Exclude) > 128 || t.Stack != "" && t.Stack != "system" && t.Stack != "gvisor" {
		return identity.Err(identity.Invalid, "invalid TUN settings")
	}
	families := map[bool]bool{}
	for _, raw := range t.Addresses {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.String() != raw || p.Addr().Is4In6() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Bits() > p.Addr().BitLen()-2 || !p.Contains(p.Addr().Next()) || families[p.Addr().Is4()] {
			return identity.Err(identity.Invalid, "TUN requires one usable address range per family")
		}
		families[p.Addr().Is4()] = true
		if p.Addr().Is4() && (p.Addr() == p.Masked().Addr() || !p.Contains(p.Addr().Next().Next())) {
			return identity.Err(identity.Invalid, "TUN requires usable host and adjacent gateway addresses")
		}
	}
	for _, values := range [][]string{t.Include, t.Exclude} {
		seen := map[string]bool{}
		for _, raw := range values {
			p, err := netip.ParsePrefix(raw)
			if err != nil || p.Addr().Is4In6() || p.Masked().String() != raw || !families[p.Addr().Is4()] || seen[raw] {
				return identity.Err(identity.Invalid, "invalid canonical TUN route prefix")
			}
			seen[raw] = true
		}
	}
	if !t.AutoRoute && (len(t.Include) > 0 || len(t.Exclude) > 0) {
		return identity.Err(identity.Invalid, "route capture settings require auto_route")
	}
	return nil
}
