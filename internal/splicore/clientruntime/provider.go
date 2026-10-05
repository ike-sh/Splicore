package clientruntime

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

type unavailableDialer struct{}

func (unavailableDialer) DialContext(context.Context, access.Endpoint) (net.Conn, error) {
	return nil, identity.Err(identity.Unavailable, "node disabled or unavailable")
}
func (unavailableDialer) Close() error { return nil }

// FetchNetwork retains one committed runtime generation throughout a fetch.
// DIRECT endpoints own a temporary infrastructure lease; proxy destinations
// use existing outbound adapters and never a second routing implementation.
type FetchNetwork struct {
	gen    *snapshot
	lease  *underlay.Lease
	direct *underlay.Dialer
	action P.Action
	once   sync.Once
}

func (m *Manager) OpenFetch(ctx context.Context, a P.Action) (*FetchNetwork, error) {
	g := m.acquire()
	if g == nil {
		return nil, identity.Err(identity.Unavailable, "provider bootstrap runtime unavailable")
	}
	if !g.state.Enabled {
		g.release()
		return nil, identity.Err(identity.Unavailable, "client runtime stopped")
	}
	f := &FetchNetwork{gen: g, action: a}
	var e error
	f.lease, e = m.underlay.Begin(ctx, tunSpec(g.state) != nil)
	if e != nil {
		g.release()
		return nil, e
	}
	f.direct, e = m.underlay.New(underlay.Scope{Purpose: underlay.ProviderFetch, Generation: f.lease.ID})
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func (f *FetchNetwork) Close() error {
	var e error
	f.once.Do(func() { e = f.lease.Close(); e = errors.Join(e, f.gen.release()) })
	return e
}
func (f *FetchNetwork) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	return f.gen.network.Bootstrap(ctx, host)
}
func (f *FetchNetwork) Dial(ctx context.Context, target access.Endpoint) (net.Conn, error) {
	a, e := f.gen.network.Select(f.action, nil, true, 0)
	if e != nil {
		return nil, e
	}
	if a.Kind == P.Direct || a.Kind == P.Outbound && a.ID == "direct" {
		ip, e := netip.ParseAddr(target.Host)
		if e != nil {
			return nil, identity.Err(identity.Invalid, "provider target must be pinned")
		}
		if e = f.lease.AddEndpoint(ctx, underlay.Scope{Purpose: underlay.ProviderFetch}, []netip.Addr{ip}); e != nil {
			return nil, e
		}
		return f.direct.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(target.Port))))
	}
	if a.Kind != P.Outbound || f.gen.outbounds[a.ID] == nil {
		return nil, identity.Err(identity.Unavailable, "provider fetch action unavailable")
	}
	return f.gen.outbounds[a.ID].DialContext(ctx, target)
}
