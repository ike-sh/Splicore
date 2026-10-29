package native

import (
	"context"
	"net"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowquic"
	"github.com/ike-sh/Splicore/protocol/shadowquic/session"
)

type ShadowQUICOutboundFactory struct{}

func (ShadowQUICOutboundFactory) Capability() ports.OutboundCapability {
	return clientconfig.Capability("shadowquic", true, session.Enabled(), false)
}

func (ShadowQUICOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return module.ValidateClient(n, c)
}

func (f ShadowQUICOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	o, _ := module.DecodeClient(n.Options.Data)
	socket, err := clientconfig.PacketSocket(ctx, n.Endpoint)
	if err != nil {
		return nil, err
	}
	p, _ := module.Pair(c.Payload)
	transport, err := session.NewClient(session.ClientConfig{ServerName: n.Security.TLS.ServerName, UDPOverStream: o.UDPOverStream, User: session.User{Username: p.Username.Reveal(), Password: p.Password.Reveal()}, Limits: o.Limits, Socket: socket})
	if err != nil {
		return nil, err
	}
	return &shadowQUICDialer{client: transport, owner: clientio.New()}, nil
}

type shadowQUICDialer struct {
	client *session.Client
	owner  *clientio.Owner
}

func (d *shadowQUICDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, err := d.client.Open(ctx, dst)
	if err != nil {
		return nil, err
	}
	return d.owner.Conn(c)
}

func (d *shadowQUICDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
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
func (d *shadowQUICDialer) Close() error { d.owner.Close(); return d.client.Close() }
