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
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

// Each box owns one adapter and its pools; no server or other outbound context is shared.
func buildClientBox(ctx context.Context, protocol string, options any, register func(*outbound.Registry)) (ports.ClientDialer, error) {
	runtimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	runtimeCtx = service.ContextWith[adapter.PlatformInterface](runtimeCtx, serverPlatform{})
	or := outbound.NewRegistry()
	register(or)
	dr := dns.NewTransportRegistry()
	local.RegisterTransport(dr)
	runtimeCtx = box.Context(runtimeCtx, inbound.NewRegistry(), or, endpoint.NewRegistry(), dr, boxservice.NewRegistry(), certificate.NewRegistry())
	b, err := box.New(box.Options{Context: runtimeCtx, Options: option.Options{
		Log:       &option.LogOptions{Disabled: true},
		DNS:       &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: []option.DNSServerOptions{{Type: "local", Tag: "local", Options: &option.LocalDNSServerOptions{}}}}},
		Outbounds: []option.Outbound{{Type: protocol, Tag: "managed", Options: options}},
	}})
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

func clientOwnership(n client.RemoteNode, c access.Credential) error {
	if n.Validate() != nil || c.OwnerNodeID == nil || *c.OwnerNodeID != n.ID || c.ID != n.CredentialID {
		return identity.Err(identity.Invalid, "node credential ownership mismatch")
	}
	return nil
}
func clientTLS(n client.RemoteNode) option.OutboundTLSOptionsContainer {
	if n.Security.Kind == "none" {
		return option.OutboundTLSOptionsContainer{}
	}
	s := n.Security.TLS
	t := &option.OutboundTLSOptions{Enabled: true, ServerName: s.ServerName, ALPN: badoption.Listable[string](append([]string(nil), s.ALPN...))}
	if s.CACertificate != "" {
		t.Certificate = badoption.Listable[string]{s.CACertificate}
	}
	if n.Security.Kind == "reality" {
		t.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
		t.Reality = &option.OutboundRealityOptions{Enabled: true, PublicKey: s.RealityPublicKey, ShortID: s.RealityShortID}
	}
	return option.OutboundTLSOptionsContainer{TLS: t}
}

func clientCapability(protocol string, tls, quic, reality bool) ports.OutboundCapability {
	return ports.OutboundCapability{Protocol: protocol, Engine: "native", Role: "client_outbound", TCP: true, UDP: true, IPv4: true, IPv6: true, Domain: true, TLS: tls, QUIC: quic, Reality: reality, Flows: []string{"none"}, UDPDomainResolution: "remote", Qualification: "experimental"}
}
