package native

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"

	"github.com/ike-sh/Splicore/protocol/hysteria2/backend"
)

type Hysteria2OutboundFactory struct{}

func (Hysteria2OutboundFactory) Capability() ports.OutboundCapability {
	return clientconfig.Capability("hysteria2", true, true, false)
}
func (Hysteria2OutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if err := clientconfig.Ownership(n, c); err != nil {
		return err
	}
	var empty struct{}
	if n.Protocol != module.Key() || n.Transport.Kind != "quic" && n.Transport.Kind != "hysteria" || n.Security.Kind != "tls" || jsonstrict.Decode(n.Options.Data, &empty) != nil || n.Transport.HysteriaSettings().Masquerade != nil || n.Transport.HysteriaSettings().DisableUDP {
		return identity.Err(identity.Invalid, "unsupported Hysteria2 client settings")
	}
	return (module.Module{}).ValidateCredential(c)
}
func (f Hysteria2OutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	tlsConfig, err := clientconfig.TLS(n.Security.TLS, n.Endpoint.Host)
	if err != nil {
		return nil, err
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	socket, err := clientconfig.PacketSocket(ctx, n.Endpoint)
	if err != nil {
		return nil, err
	}
	config := backend.ClientConfig{TLS: tlsConfig, Password: c.Payload.(access.PasswordPayload).Password.Reveal(), Socket: socket, Transport: n.Transport.HysteriaSettings()}
	client, err := backend.NewClient(ctx, config)
	if err != nil {
		return nil, err
	}
	return &hysteria2Dialer{client: client, owner: clientio.New()}, nil
}

type hysteria2Dialer struct {
	client *backend.Client
	owner  *clientio.Owner
}

func (d *hysteria2Dialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, err := d.client.OpenTCP(ctx, dst)
	if err != nil {
		return nil, err
	}
	return d.owner.Conn(c)
}
func (d *hysteria2Dialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	p, err := d.client.OpenPacket(ctx, dst)
	if err != nil {
		return nil, err
	}
	return d.owner.Packet(p)
}
func (d *hysteria2Dialer) Close() error { d.owner.Close(); d.client.Close(); return nil }
