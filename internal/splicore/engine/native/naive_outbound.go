package native

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/naive"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/naive/backend"
	"net"
)

type NaiveOutboundFactory struct{}

func (NaiveOutboundFactory) Capability() ports.OutboundCapability {
	c := clientconfig.Capability("naive", true, backend.H3Enabled(), false)
	c.UDP = false
	c.UDPDomainResolution = "unsupported"
	return c
}
func (NaiveOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return module.ValidateClient(n, c)
}
func (f NaiveOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	o, _ := module.DecodeClient(n.Options.Data)
	tc, err := clientconfig.TLS(n.Security.TLS, n.Endpoint.Host)
	if err != nil {
		return nil, err
	}
	dialer, err := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if err != nil {
		return nil, err
	}
	connect, _ := module.Duration(o.ConnectTimeout, "5s")
	tunnel, _ := module.Duration(o.TunnelTimeout, "30m")
	idle, _ := module.Duration(o.IdleTimeout, "10m")
	payload := c.Payload.(access.UsernamePasswordPayload)
	config := backend.ClientConfig{Mode: o.Mode, Proxy: net.JoinHostPort(n.Endpoint.Host, portString(n.Endpoint.Port)),
		Username: payload.Username.Reveal(), Password: payload.Password.Reveal(), TLS: tc, DialTCP: dialer.DialContext,
		Padding: o.Padding, Headers: o.Headers(), MaxConnections: o.MaxConnections, MaxStreams: o.MaxStreams, ConnectTimeout: connect, TunnelTimeout: tunnel, IdleTimeout: idle}
	if o.Mode == "quic" {
		config.PacketSocket, err = clientconfig.PacketSocket(ctx, n.Endpoint)
		if err != nil {
			return nil, err
		}
	}
	transport, err := backend.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &naiveDialer{client: transport, owner: clientio.New()}, nil
}

type naiveDialer struct {
	client *backend.Client
	owner  *clientio.Owner
}

func (d *naiveDialer) SupportsNetwork(network string) bool { return network == "tcp" }
func (d *naiveDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	if dst.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "invalid Naive destination")
	}
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	conn, err := d.client.Open(ctx, net.JoinHostPort(dst.Host, portString(dst.Port)))
	if err != nil {
		return nil, err
	}
	return d.owner.Conn(conn)
}
func (d *naiveDialer) ListenPacket(context.Context, access.Endpoint) (net.PacketConn, error) {
	return nil, identity.Err(identity.NotImplemented, "Naive native UDP payload is not implemented")
}
func (d *naiveDialer) Close() error { d.owner.Close(); return d.client.Close() }
