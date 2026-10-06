package clientruntime

import (
	"context"
	"encoding/json"
	"net/netip"
	"net/url"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func resolveNode(ctx context.Context, b *networkruntime.Engine, host string, resolve bool) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return underlay.Normalize([]netip.Addr{ip})
	}
	if !resolve {
		return nil, nil
	}
	ips, err := b.Bootstrap(ctx, host)
	if err != nil {
		return nil, identity.Err(identity.Unavailable, "remote node bootstrap resolution failed")
	}
	return underlay.Normalize(ips)
}
func resolvedKey(ips []netip.Addr) string { b, _ := json.Marshal(ips); return string(b) }

func (p *Prepared) prepareInfrastructure(ctx context.Context, b *networkruntime.Engine) error {
	for _, s := range p.s.state.Network.Servers {
		if s.Type == "system" {
			continue
		}
		ips, err := resolveNode(ctx, b, s.Endpoint.Host, true)
		if err != nil {
			return err
		}
		purpose := underlay.DNSUpstream
		if s.ID == p.s.state.Network.DNS.BootstrapServer {
			purpose = underlay.DNSBootstrap
		}
		if err = p.s.underlay.AddEndpoint(ctx, underlay.Scope{Purpose: purpose, Runtime: s.ID}, ips); err != nil {
			return err
		}
	}
	for _, g := range p.s.state.Network.Groups {
		probe := g.Probe()
		if probe == nil {
			continue
		}
		u, err := url.Parse(probe.URL)
		if err != nil {
			return err
		}
		ips, err := resolveNode(ctx, b, u.Hostname(), true)
		if err != nil {
			return err
		}
		if err = p.s.underlay.AddEndpoint(ctx, underlay.Scope{Purpose: underlay.HealthProbe, Runtime: g.ID}, ips); err != nil {
			return err
		}
	}
	return nil
}
