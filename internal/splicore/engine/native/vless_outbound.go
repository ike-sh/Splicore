package native

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/option"
	upstream "github.com/sagernet/sing-box/protocol/vless"
)

type VLESSOutboundFactory struct{}

func (VLESSOutboundFactory) Capability() ports.OutboundCapability {
	return clientCapability("vless", true, false, true)
}
func (VLESSOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return module.ValidateClientNode(n, c)
}
func (f VLESSOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	encoding := "xudp"
	return buildClientBox(ctx, "vless", &option.VLESSOutboundOptions{ServerOptions: option.ServerOptions{Server: n.Endpoint.Host, ServerPort: n.Endpoint.Port}, UUID: c.Payload.(access.UUIDPayload).UUID.Reveal(), PacketEncoding: &encoding, OutboundTLSOptionsContainer: clientTLS(n)}, upstream.RegisterOutbound)
}
