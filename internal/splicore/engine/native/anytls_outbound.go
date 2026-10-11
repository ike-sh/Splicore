package native

import (
	"context"
	"net"
	"sync"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/anytls"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/uot2"
	shared "github.com/ike-sh/Splicore/internal/splicore/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/anytls/session"
	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

type AnyTLSOutboundFactory struct{}

func (AnyTLSOutboundFactory) Capability() ports.OutboundCapability {
	return clientconfig.Capability("anytls", true, false, false)
}
func (AnyTLSOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return module.ValidateClientNode(n, c)
}
func (f AnyTLSOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	protected, err := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if err != nil {
		return nil, err
	}
	tc, err := clientconfig.TLS(n.Security.TLS, n.Endpoint.Host)
	if err != nil {
		return nil, err
	}
	options, _ := module.DecodeClientOptions(n.Options.Data)
	// This override is AnyTLS-specific, explicit and false by default. It never
	// modifies canonical shared TLS trust or another protocol's configuration.
	tc.InsecureSkipVerify = options.Insecure
	cfg := options.PoolConfig()
	cfg.Session.OnAlert = anytlsAlert
	key := wire.PasswordKey(c.Payload.(access.PasswordPayload).Password.Reveal())
	defer clear(key[:])
	pool, err := session.NewClientPool(func(ctx context.Context) (net.Conn, error) {
		return shared.Dial(ctx, protected.DialContext, net.JoinHostPort(n.Endpoint.Host, portString(n.Endpoint.Port)), n.Transport, tc)
	}, key, cfg)
	if err != nil {
		return nil, err
	}
	owner := clientio.New()
	if _, err = owner.Track(pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &anytlsDialer{pool: pool, owner: owner, udp: options.UDP, connectUDP: options.UOTMode == "connect"}, nil
}

type anytlsDialer struct {
	pool            *session.Client
	owner           *clientio.Owner
	udp, connectUDP bool
	once            sync.Once
}

func (d *anytlsDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	if dst.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "invalid AnyTLS destination")
	}
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	data, err := address.MarshalSOCKS(dst)
	if err != nil {
		return nil, err
	}
	stream, err := d.pool.Open(ctx, data)
	if err != nil {
		return nil, err
	}
	return d.owner.Conn(stream)
}
func (d *anytlsDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	if !d.udp {
		return nil, identity.Err(identity.NotImplemented, "AnyTLS UDP is disabled")
	}
	if dst.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "invalid AnyTLS UDP destination")
	}
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	magic, _ := address.MarshalSOCKS(access.Endpoint{Host: uot2.MagicHost, Port: 0})
	request := uot2.Request{Connect: d.connectUDP, Destination: dst}
	if !request.Connect {
		request.Destination = access.Endpoint{Host: "0.0.0.0", Port: 0}
	}
	initial, err := uot2.MarshalRequest(request)
	if err != nil {
		return nil, err
	}
	// Reference servers may acknowledge only after reading the UoT request.
	// Submit it with the reserved destination before waiting for SYNACK.
	stream, err := d.pool.Open(ctx, append(magic, initial...))
	if err != nil {
		return nil, err
	}
	packet, err := uot2.ClientAfterRequest(stream, request)
	if err != nil {
		return nil, err
	}
	return d.owner.Packet(packet)
}
func (d *anytlsDialer) SupportsNetwork(network string) bool {
	return network == "tcp" || network == "udp" && d.udp
}
func (d *anytlsDialer) Close() error { d.once.Do(func() { d.owner.Close() }); return nil }
