package client

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
)

type TunnelSettings struct {
	Target  access.Endpoint `json:"target"`
	Network string          `json:"network"`
}

type SniffingPolicy struct {
	Enabled   bool     `json:"enabled"`
	Protocols []string `json:"protocols"`
	RouteOnly bool     `json:"route_only"`
}

func tunnelError(message string) error { return identity.Err(identity.Invalid, message) }

// All Phase29.1 tunnel listeners are protected local guards. Explicit IP
// literals avoid DNS-dependent listener exposure; allow_lan cannot override it.
func (i LocalInbound) validateTunnel() error {
	if i.Listen.Validate() != nil || (i.Listen.Host != "127.0.0.1" && i.Listen.Host != "::1") || i.AllowLAN {
		return tunnelError("tunnel guard listen must be 127.0.0.1 or ::1 with a valid port; allow_lan is prohibited")
	}
	if i.TUN != nil || i.Auth || len(i.Bindings) != 0 || i.SelectedOutbound != "" {
		return tunnelError("tunnel guard cannot use TUN, proxy authentication, bindings or selected_outbound")
	}
	if i.Tunnel == nil || i.Tunnel.Target.Validate() != nil {
		return tunnelError("tunnel requires a valid configured target address and port")
	}
	if i.Tunnel.Network != "tcp" {
		return tunnelError("tunnel guard supports network tcp only; UDP is not admitted")
	}
	if i.Sniffing == nil || !i.Sniffing.Enabled || !i.Sniffing.RouteOnly || len(i.Sniffing.Protocols) != 1 || i.Sniffing.Protocols[0] != "tls" {
		return tunnelError("tunnel guard requires enabled TLS-only route_only sniffing")
	}
	target, listen := i.Tunnel.Target, i.Listen
	ip, err := netip.ParseAddr(target.Host)
	local, _ := netip.ParseAddr(listen.Host)
	if target.Port == listen.Port && (err == nil && ip.Unmap() == local || strings.EqualFold(strings.TrimSuffix(target.Host, "."), "localhost")) {
		return tunnelError("tunnel configured target points to its own listener")
	}
	return nil
}

// Allows a newly created guard with no applicable rules to remain dormant
// (closed). Once allows exist, an explicit scoped reject must follow them.
// Conservatively reject any earlier broad rule that could bypass the guard.
func (s ProfileState) validateTunnelRoutes() error {
	for _, i := range s.LocalInbounds {
		if i.Kind != "tunnel" {
			continue
		}
		allowed, terminal := false, false
		for _, r := range s.Network.Route.Rules {
			m := r.Match
			if len(m.LocalInbounds) > 0 && !slices.Contains(m.LocalInbounds, i.ID) {
				continue
			}
			if len(m.LocalInbounds) != 1 || m.LocalInbounds[0] != i.ID {
				return tunnelError("tunnel routes before fallback must explicitly scope one guard local_inbounds ID")
			}
			if r.Action.Kind == P.Reject && len(m.Domains)+len(m.SniffedDomains)+len(m.Suffixes)+len(m.Keywords)+len(m.CIDRs)+len(m.Ports)+len(m.Networks)+len(m.RuleSets) == 0 {
				terminal = true
				break
			}
			if r.Action != (P.Action{Kind: P.Direct}) || len(m.SniffedDomains) == 0 || len(m.Domains)+len(m.Suffixes)+len(m.Keywords)+len(m.CIDRs)+len(m.RuleSets) != 0 || len(m.Networks) > 0 && (len(m.Networks) != 1 || m.Networks[0] != "tcp") {
				return tunnelError("tunnel allow requires exact sniffed_domains and native direct before scoped reject")
			}
			allowed = true
		}
		if allowed && !terminal {
			return tunnelError("tunnel allow rules require a following inbound-only reject fallback")
		}
	}
	return nil
}
