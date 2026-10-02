package native

import (
	"context"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"github.com/sagernet/sing-box/option"
	upstream "github.com/sagernet/sing-box/protocol/snell"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"net"
)

// SnellOutboundFactory belongs to the existing native engine; no wire implementation.
type SnellOutboundFactory struct{}

func (SnellOutboundFactory) Capability() ports.OutboundCapability {
	return ports.OutboundCapability{Protocol: "snell", Engine: "native", TCP: true, UDP: true, Qualification: "experimental"}
}
func (SnellOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if err := n.Validate(); err != nil {
		return err
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
	runtimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	runtimeCtx = service.ContextWith[adapter.PlatformInterface](runtimeCtx, serverPlatform{})
	or := outbound.NewRegistry()
	upstream.RegisterOutbound(or)
	dr := dns.NewTransportRegistry()
	local.RegisterTransport(dr)
	runtimeCtx = box.Context(runtimeCtx, inbound.NewRegistry(), or, endpoint.NewRegistry(), dr, boxservice.NewRegistry(), certificate.NewRegistry())
	opts := &option.SnellOutboundOptions{AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{ServerOptions: option.ServerOptions{Server: n.Endpoint.Host, ServerPort: n.Endpoint.Port}, PSK: c.Payload.(access.PSKPayload).Key.Reveal()}, Version: v}
	b, err := box.New(box.Options{Context: runtimeCtx, Options: option.Options{Log: &option.LogOptions{Disabled: true}, DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: []option.DNSServerOptions{{Type: "local", Tag: "local", Options: &option.LocalDNSServerOptions{}}}}}, Outbounds: []option.Outbound{{Type: "snell", Tag: "managed", Options: opts}}}})
	if err != nil {
		cancel()
		return nil, identity.Err(identity.Unavailable, "native outbound construction failed")
	}
	if err = b.Start(); err != nil {
		_ = b.Close()
		cancel()
		return nil, identity.Err(identity.Unavailable, "native outbound start failed")
	}
	o, ok := b.Outbound().Outbound("managed")
	if !ok {
		_ = b.Close()
		cancel()
		return nil, identity.Err(identity.Unavailable, "native outbound unavailable")
	}
	return &snellDialer{box: b, outbound: o, cancel: cancel}, nil
}

type snellDialer struct {
	box      *box.Box
	outbound adapter.Outbound
	cancel   context.CancelFunc
}

func (d *snellDialer) DialContext(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	return d.outbound.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort(e.Host, e.Port))
}
func (d *snellDialer) Close() error { d.cancel(); return d.box.Close() }
func (d *snellDialer) ListenPacket(ctx context.Context, e access.Endpoint) (net.PacketConn, error) {
	return d.outbound.ListenPacket(ctx, M.ParseSocksaddrHostPort(e.Host, e.Port))
}
