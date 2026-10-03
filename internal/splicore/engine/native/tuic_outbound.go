package native

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	"github.com/sagernet/sing-box/option"
	upstream "github.com/sagernet/sing-box/protocol/tuic"
)

type TUICOutboundFactory struct{}

func (TUICOutboundFactory) Capability() ports.OutboundCapability {
	return clientCapability("tuic", true, true, false)
}
func (TUICOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if err := clientOwnership(n, c); err != nil {
		return err
	}
	if _, err := module.DecodeClientOptions(n.Options.Data); err != nil {
		return err
	}
	if n.Protocol != module.Key() || n.Transport.Kind != "quic" || n.Security.Kind != "tls" {
		return identity.Err(identity.Invalid, "unsupported TUIC client settings")
	}
	return (module.Module{}).ValidateCredential(c)
}
func (f TUICOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	p := c.Payload.(access.UUIDPasswordPayload)
	return buildClientBox(ctx, "tuic", &option.TUICOutboundOptions{ServerOptions: option.ServerOptions{Server: n.Endpoint.Host, ServerPort: n.Endpoint.Port}, UUID: p.UUID.Reveal(), Password: p.Password.Reveal(), CongestionControl: "cubic", UDPRelayMode: "native", OutboundTLSOptionsContainer: clientTLS(n)}, upstream.RegisterOutbound)
}
