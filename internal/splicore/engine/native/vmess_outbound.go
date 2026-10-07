package native

import (
	"context"
	"crypto/tls"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vmess/backend"
	"github.com/ike-sh/Splicore/protocol/vmess/wire"
	"net"
	"time"
)

type VMessOutboundFactory struct{}

func (VMessOutboundFactory) Capability() ports.OutboundCapability {
	return clientconfig.Capability("vmess", true, false, true)
}
func (VMessOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return module.ValidateClientNode(n, c)
}
func (f VMessOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	d, err := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if err != nil {
		return nil, err
	}
	var tc *tls.Config
	if n.Security.Kind == "tls" {
		tc, err = clientconfig.TLS(n.Security.TLS, n.Endpoint.Host)
		if err != nil {
			return nil, err
		}
	}
	opts, _ := module.DecodeClientOptions(n.Options.Data)
	security, _ := module.Security(opts.Security)
	return &vmessDialer{protected: d, node: n, key: module.CommandKey(c.Payload.(access.UUIDPayload)), security: security, udp: opts.UDP, tls: tc, owner: clientio.New()}, nil
}

type vmessDialer struct {
	protected *underlay.Dialer
	node      client.RemoteNode
	key       wire.Key
	security  byte
	udp       bool
	tls       *tls.Config
	owner     *clientio.Owner
}

func (d *vmessDialer) open(ctx context.Context, dst access.Endpoint, packet bool) (*backend.Conn, error) {
	command, options := wire.TCP, byte(wire.ChunkStream|wire.LengthMask|wire.GlobalPadding)
	if packet {
		command = wire.UDP
	}
	if d.security == wire.None {
		options = wire.ChunkStream | wire.LengthMask
		if !packet {
			options = 0
		}
	}
	r, err := wire.NewRequest(dst, command, d.security, options, nil)
	if err != nil {
		return nil, err
	}
	c, err := d.protected.DialContext(ctx, "tcp", net.JoinHostPort(d.node.Endpoint.Host, portString(d.node.Endpoint.Port)))
	if err != nil {
		return nil, err
	}
	raw := c
	success := false
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = raw.Close(); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	_ = raw.SetDeadline(deadline)
	if d.tls != nil {
		tc := tls.Client(raw, d.tls.Clone())
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		c = tc
	}
	// Published sockets are owned by clientio, independently of the dial context.
	stream, err := backend.Client(context.WithoutCancel(ctx), c, d.key, r, time.Now())
	if err != nil {
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	success = true
	return stream, nil
}
func (d *vmessDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, err := d.open(ctx, dst, false)
	if err != nil {
		return nil, err
	}
	return d.owner.Conn(c)
}
func (d *vmessDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	if !d.udp {
		return nil, module.Unsupported("VMess UDP disabled")
	}
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, err := d.open(ctx, dst, true)
	if err != nil {
		return nil, err
	}
	return d.owner.Packet(backend.NewPacket(context.Background(), c, dst))
}
func (d *vmessDialer) Close() error { d.owner.Close(); return nil }
