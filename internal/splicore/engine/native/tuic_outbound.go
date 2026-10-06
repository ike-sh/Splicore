package native

import (
	"context"
	"github.com/gofrs/uuid/v5"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/tuic"
	"github.com/ike-sh/Splicore/protocol/tuic/backend"
	"net"
)

type TUICOutboundFactory struct{}

func (TUICOutboundFactory) Capability() ports.OutboundCapability {
	return clientconfig.Capability("tuic", true, true, false)
}
func (TUICOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if err := clientconfig.Ownership(n, c); err != nil {
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
	tc, err := clientconfig.TLS(n.Security.TLS, n.Endpoint.Host)
	if err != nil {
		return nil, err
	}
	socket, err := clientconfig.PacketSocket(ctx, n.Endpoint)
	if err != nil {
		return nil, err
	}
	p := c.Payload.(access.UUIDPasswordPayload)
	u, _ := uuid.FromString(p.UUID.Reveal())
	return &tuicDialer{config: backend.ClientConfig{TLS: tc, UUID: [16]byte(u), Password: p.Password.Reveal(), Socket: socket}, owner: clientio.New()}, nil
}

type tuicDialer struct {
	config backend.ClientConfig
	owner  *clientio.Owner
}

func (d *tuicDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, err := backend.OpenTCP(ctx, d.config, dst)
	if err != nil {
		return nil, err
	}
	return d.owner.Conn(c)
}
func (d *tuicDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	p, err := backend.OpenPacket(ctx, d.config, dst)
	if err != nil {
		return nil, err
	}
	return d.owner.Packet(p)
}
func (d *tuicDialer) Close() error { d.owner.Close(); return nil }
