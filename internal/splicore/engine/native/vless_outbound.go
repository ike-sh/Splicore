package native

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/gofrs/uuid/v5"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	shared "github.com/ike-sh/Splicore/internal/splicore/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vless/backend"
	"github.com/ike-sh/Splicore/protocol/vless/vision"
	"net"
	"time"
)

type VLESSOutboundFactory struct{}

func (VLESSOutboundFactory) Capability() ports.OutboundCapability {
	c := clientconfig.Capability("vless", true, false, true)
	c.Flows = append(c.Flows, string(module.Vision))
	return c
}
func (VLESSOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return module.ValidateClientNode(n, c)
}
func (f VLESSOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	n.Transport = n.Transport.Clone()
	d, err := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if err != nil {
		return nil, err
	}
	u, _ := uuid.FromString(c.Payload.(access.UUIDPayload).UUID.Reveal())
	var tc *tls.Config
	if n.Security.Kind == "tls" {
		tc, err = clientconfig.TLS(n.Security.TLS, n.Endpoint.Host)
		if err != nil {
			return nil, err
		}
	}
	options, _ := module.DecodeClientOptions(n.Options.Data)
	transport, err := sharedClient(d.DialContext, n, tc)
	if err != nil {
		return nil, err
	}
	if options.Flow == module.Vision && tc != nil {
		tc.MinVersion = tls.VersionTLS13
	}
	return &vlessDialer{transport: transport, flow: options.Flow, protected: d, node: n, uuid: [16]byte(u), tls: tc, owner: clientio.New()}, nil
}

type vlessDialer struct {
	transport *shared.Client
	flow      module.Flow
	protected *underlay.Dialer
	node      client.RemoteNode
	uuid      [16]byte
	tls       *tls.Config
	owner     *clientio.Owner
}

func (d *vlessDialer) open(ctx context.Context, dst access.Endpoint, packet bool) (net.Conn, error) {
	tc := d.tls
	if d.flow == module.Vision {
		if packet {
			return nil, errors.New("Vision packet sessions are outside the supported TCP profile")
		}
		tc = nil
	}
	var c net.Conn
	var err error
	if d.transport != nil {
		c, err = d.transport.DialContext(ctx)
	} else {
		c, err = shared.Dial(ctx, d.protected.DialContext, net.JoinHostPort(d.node.Endpoint.Host, portString(d.node.Endpoint.Port)), d.node.Transport, tc)
	}
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
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	admission, finish := shared.BeginAdmission(raw, 5*time.Second)
	c = admission
	defer func() {
		if !success {
			admission.Close()
		}
	}()

	if d.flow == module.Vision {
		c = vision.LimitRecords(admission)
		if d.tls != nil {
			secure := tls.Client(c, d.tls)
			if err = secure.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			c = secure
		}
	}
	if d.node.Security.Kind == "reality" && d.transport == nil {
		c, err = backend.RealityClient(ctx, c, d.node.Security.TLS)
		if err != nil {
			return nil, err
		}
	}
	var plain *vision.PlainConn
	flow := ""
	if d.flow == module.Vision {
		plain = vision.BufferRecords(c)
		c = plain
		flow = vision.Flow
	}
	c, err = backend.ClientFlow(ctx, c, d.uuid, dst, packet, flow)
	if err != nil {
		return nil, err
	}
	if d.flow == module.Vision {
		c = vision.New(c, plain, raw, d.uuid)
	}
	if err = finish(); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	success = true
	return c, nil
}
func (d *vlessDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
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
func (d *vlessDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	ctx, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, err := d.open(ctx, dst, true)
	if err != nil {
		return nil, err
	}
	return d.owner.Packet(backend.NewClientPacket(c, dst))
}
func (d *vlessDialer) Close() error {
	d.owner.Close()
	if d.transport != nil {
		d.transport.Close()
	}
	return nil
}
