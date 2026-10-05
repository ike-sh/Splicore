package networkruntime

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"net/netip"
)

func (e *Engine) systemLookup(ctx context.Context, network, domain string) ([]netip.Addr, error) {
	ctx, done, err := e.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	d, err := e.underlay.New(underlay.Scope{Purpose: underlay.DNSBootstrap, Generation: e.generation})
	if err != nil {
		return nil, err
	}
	return d.LookupNetIP(ctx, network, domain)
}
