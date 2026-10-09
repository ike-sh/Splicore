package native

import (
	"context"
	"crypto/tls"
	shared "github.com/ike-sh/Splicore/internal/splicore/streamtransport"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/trojan/backend"
	"github.com/ike-sh/Splicore/protocol/trojan/wire"
)

type TrojanOutboundFactory struct{}

func (TrojanOutboundFactory) Capability() ports.OutboundCapability {
	return clientconfig.Capability("trojan", true, false, true)
}
func (TrojanOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return module.ValidateClientNode(n, c)
}
func (f TrojanOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	n.Transport = n.Transport.Clone()
	d, err := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if err != nil {
		return nil, err
	}
	t, err := clientconfig.TLS(n.Security.TLS, n.Endpoint.Host)
	if err != nil {
		return nil, err
	}
	o, _ := module.DecodeClientOptions(n.Options.Data)
	return &trojanDialer{protected: d, node: n, key: wire.Derive(c.Payload.(access.PasswordPayload).Password), tls: t, udp: o.UDP, owner: clientio.New()}, nil
}

type trojanDialer struct {
	protected *underlay.Dialer
	node      client.RemoteNode
	key       wire.Key
	tls       *tls.Config
	udp       bool
	owner     *clientio.Owner
	once      sync.Once
}

func (d *trojanDialer) open(ctx context.Context, dst access.Endpoint, command byte) (net.Conn, error) {
	if dst.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "invalid Trojan destination")
	}
	raw, err := shared.Dial(ctx, d.protected.DialContext, net.JoinHostPort(d.node.Endpoint.Host, portString(d.node.Endpoint.Port)), d.node.Transport, d.tls)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = raw.Close(); close(callbackDone) })
	defer func() {
		if !stop() {
			<-callbackDone
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	_ = raw.SetDeadline(deadline)
	c := &backend.Stream{Conn: raw, Raw: raw}
	if err = backend.Client(c, d.key, command, dst); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	success = true
	return c, nil
}
func (d *trojanDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, err := d.open(ctx, dst, wire.Connect)
	if err != nil {
		return nil, err
	}
	return d.owner.Conn(c)
}
func (d *trojanDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	if !d.udp {
		return nil, identity.Err(identity.NotImplemented, "Trojan UDP is disabled")
	}
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, err := d.open(ctx, dst, wire.Associate)
	if err != nil {
		return nil, err
	}
	return d.owner.Packet(backend.NewPacket(context.Background(), c))
}
func (d *trojanDialer) Close() error {
	d.once.Do(func() { d.owner.Close(); clear(d.key[:]) })
	return nil
}
