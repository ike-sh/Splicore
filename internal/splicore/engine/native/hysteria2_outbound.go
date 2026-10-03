package native

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	"github.com/sagernet/sing-box/option"
	upstream "github.com/sagernet/sing-box/protocol/hysteria2"
)

type Hysteria2OutboundFactory struct{}

func (Hysteria2OutboundFactory) Capability() ports.OutboundCapability {
	return clientCapability("hysteria2", true, true, false)
}
func (Hysteria2OutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if err := clientOwnership(n, c); err != nil {
		return err
	}
	var empty struct{}
	if n.Protocol != module.Key() || n.Transport.Kind != "quic" || n.Security.Kind != "tls" || jsonstrict.Decode(n.Options.Data, &empty) != nil {
		return identity.Err(identity.Invalid, "unsupported Hysteria2 client settings")
	}
	return (module.Module{}).ValidateCredential(c)
}
func (f Hysteria2OutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	return buildClientBox(ctx, "hysteria2", &option.Hysteria2OutboundOptions{ServerOptions: option.ServerOptions{Server: n.Endpoint.Host, ServerPort: n.Endpoint.Port}, Password: c.Payload.(access.PasswordPayload).Password.Reveal(), OutboundTLSOptionsContainer: clientTLS(n)}, upstream.RegisterOutbound)
}
