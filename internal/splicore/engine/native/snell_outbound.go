package native

import (
	"context"
	"net"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
)

type SnellOutboundFactory struct{}

func (SnellOutboundFactory) Capability() ports.OutboundCapability {
	c := clientconfig.Capability("snell", false, false, false)
	c.UDPDomainResolution = "local"
	return c
}
func (SnellOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if e := clientconfig.Ownership(n, c); e != nil {
		return e
	}
	if n.Transport.Kind != "tcp" || n.Security.Kind != "none" {
		return identity.Err(identity.Invalid, "unsupported Snell client settings")
	}
	s, e := module.DecodeClient(n.Options.Data)
	if e != nil {
		return e
	}
	if n.Protocol != module.Key(s.Version) {
		return identity.Err(identity.Invalid, "node protocol or credential ownership mismatch")
	}
	return (module.Module{Version: s.Version}).ValidateCredential(c)
}
func (f SnellOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if e := f.Validate(n, c); e != nil {
		return nil, e
	}
	d, e := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if e != nil {
		return nil, e
	}
	resolver, e := underlay.DialerFrom(ctx, underlay.DNSBootstrap)
	if e != nil {
		return nil, e
	}
	s, _ := module.DecodeClient(n.Options.Data)
	v, _ := module.ClientVersion(s.Version)
	k, e := wire.NewKey(v, c.Payload.(access.PSKPayload).Key.Reveal())
	if e != nil {
		return nil, e
	}
	out := &snellDialer{protected: d, resolver: resolver, endpoint: n.Endpoint, key: k, options: s, owner: clientio.New()}
	if s.Reuse {
		out.pool = newSnellPool(out.dial, k)
		if _, e := out.owner.Track(out.pool); e != nil {
			_ = out.pool.Close()
			return nil, e
		}
	}
	return out, nil
}

type snellDialer struct {
	protected, resolver *underlay.Dialer
	endpoint            access.Endpoint
	key                 *wire.Key
	owner               *clientio.Owner
	options             module.ClientOptions
	pool                *snellPool
}

func (d *snellDialer) dial(ctx context.Context) (net.Conn, error) {
	return d.dialPort(ctx, d.endpoint.Port)
}
func (d *snellDialer) dialPort(ctx context.Context, port uint16) (net.Conn, error) {
	raw, e := d.protected.DialContext(ctx, "tcp", net.JoinHostPort(d.endpoint.Host, portString(port)))
	if e != nil {
		return nil, e
	}
	owned, e := d.owner.Conn(raw)
	if e == nil && d.options.ObfsMode == "http" {
		owned = wire.HTTPClient(owned, d.options.HTTPHost(), d.options.HTTPURI())
	}
	return owned, e
}
func (d *snellDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	ctx, done, e := d.owner.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	if e := dst.Validate(); e != nil {
		return nil, e
	}
	if d.pool != nil {
		return d.pool.acquire(ctx, dst)
	}
	raw, e := d.dial(ctx)
	if e != nil {
		return nil, e
	}
	var c net.Conn
	if d.options.Version == 4 {
		c, e = wire.ClientTCPNoReuse(raw, d.key, dst)
	} else {
		c, e = wire.ClientTCP(raw, d.key, dst)
	}
	if e != nil {
		_ = raw.Close()
		return nil, e
	}
	return c, nil
}
func (d *snellDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	ctx, done, e := d.owner.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	if d.options.UDP != nil && !*d.options.UDP {
		return nil, identity.Err(identity.Invalid, "Snell UDP disabled")
	}
	if e = dst.Validate(); e != nil {
		return nil, e
	}
	// Existing managed Snell UDP resolves its connected flow locally; domain
	// responses cannot be represented by the protocol's IP-only reply codec.
	if net.ParseIP(dst.Host) == nil {
		ips, e := d.resolver.LookupNetIP(ctx, "ip", dst.Host)
		if e != nil {
			return nil, e
		}
		if len(ips) == 0 {
			return nil, net.InvalidAddrError("domain has no addresses")
		}
		dst.Host = ips[0].String()
	}
	port := d.endpoint.Port
	if d.options.UDPPort != 0 {
		port = d.options.UDPPort
	}
	raw, e := d.dialPort(ctx, port)
	if e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	p, e := wire.ClientPacket(raw, d.key, dst)
	if e != nil {
		_ = raw.Close()
		return nil, e
	}
	_ = raw.SetDeadline(time.Time{})
	return &resolvedClientPacket{PacketConn: p, target: netaddr.UDP(dst)}, nil
}
func (d *snellDialer) Close() error { d.owner.Close(); return nil }
func (d *snellDialer) SupportsNetwork(network string) bool {
	return network == "tcp" || network == "udp" && (d.options.UDP == nil || *d.options.UDP)
}

type resolvedClientPacket struct {
	net.PacketConn
	target net.Addr
}

func (p *resolvedClientPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.PacketConn.WriteTo(b, p.target)
}
