package native

import (
	"context"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"github.com/sagernet/sing-box/option"
	upstream "github.com/sagernet/sing-box/protocol/snell"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"strconv"
)

// SnellOutboundFactory belongs to the existing native engine; no wire implementation.
type SnellOutboundFactory struct{}

func (SnellOutboundFactory) Capability() ports.OutboundCapability {
	c := clientCapability("snell", false, false, false)
	c.UDPDomainResolution = "local"
	return c
}
func (SnellOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if err := n.Validate(); err != nil {
		return err
	}
	if n.Transport.Kind != "tcp" || n.Security.Kind != "none" {
		return identity.Err(identity.Invalid, "unsupported Snell client settings")
	}
	s, err := module.Decode(n.Options.Data)
	if err != nil {
		return err
	}
	if n.Protocol != module.Key(s.Version) || c.OwnerNodeID == nil || *c.OwnerNodeID != n.ID || c.ID != n.CredentialID {
		return identity.Err(identity.Invalid, "node protocol or credential ownership mismatch")
	}
	return (module.Module{Version: s.Version}).ValidateCredential(c)
}
func (f SnellOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	s, _ := module.Decode(n.Options.Data)
	v, _ := module.ClientVersion(s.Version)

	opts := &option.SnellOutboundOptions{AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{ServerOptions: option.ServerOptions{Server: n.Endpoint.Host, ServerPort: n.Endpoint.Port}, PSK: c.Payload.(access.PSKPayload).Key.Reveal()}, Version: v}
	d, err := buildClientBox(ctx, "snell", opts, upstream.RegisterOutbound)
	if err == nil {
		d.(*snellDialer).resolveUDP = true
	}
	return d, err
}

type snellDialer struct {
	resolver   *underlay.Dialer
	box        *box.Box
	outbound   adapter.Outbound
	cancel     context.CancelFunc
	resolveUDP bool
}

func (d *snellDialer) DialContext(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	return d.outbound.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort(e.Host, e.Port))
}
func (d *snellDialer) Close() error { d.cancel(); return d.box.Close() }
func (d *snellDialer) ListenPacket(ctx context.Context, e access.Endpoint) (net.PacketConn, error) {
	if d.resolveUDP && net.ParseIP(e.Host) == nil {
		// The frozen native server path unmaps a domain response into a domain
		// address which Snell's IP-only response framing cannot encode. Resolve
		// this client flow once; preserve the canonical domain and the wire codec.
		address, err := d.resolver.LookupNetIP(ctx, "ip", e.Host)
		if err != nil {
			return nil, err
		}
		if len(address) == 0 {
			return nil, net.InvalidAddrError("domain has no addresses")
		}
		target := M.ParseSocksaddr(net.JoinHostPort(address[0].String(), strconv.Itoa(int(e.Port))))
		pc, err := d.outbound.ListenPacket(ctx, target)
		if err != nil {
			return nil, err
		}
		return &resolvedClientPacket{PacketConn: pc, target: target}, nil
	}
	return d.outbound.ListenPacket(ctx, M.ParseSocksaddrHostPort(e.Host, e.Port))
}

type resolvedClientPacket struct {
	net.PacketConn
	target net.Addr
}

func (p *resolvedClientPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.PacketConn.WriteTo(b, p.target)
}
