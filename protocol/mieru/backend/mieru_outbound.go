package backend

import (
	"context"
	api "github.com/enfein/mieru/v3/apis/client"
	ac "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/mieru"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"google.golang.org/protobuf/proto"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type MieruOutboundFactory struct{}

func (MieruOutboundFactory) Capability() ports.OutboundCapability {
	c := clientconfig.Capability("mieru", false, false, false)
	c.UDPDomainResolution = "local"
	return c
}
func (MieruOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if err := clientconfig.Ownership(n, c); err != nil {
		return err
	}
	s, err := module.Decode(n.Options.Data)
	if err != nil {
		return err
	}
	if n.Protocol != module.Key() || n.Transport.Kind != s.Transport || n.Security.Kind != "none" {
		return identity.Err(identity.Invalid, "unsupported Mieru client settings")
	}
	return (module.Module{}).ValidateCredential(c)
}
func (f MieruOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
		return nil, err
	}
	protected, err := underlay.DialerFrom(ctx, underlay.ProxyUnderlay)
	if err != nil {
		return nil, err
	}
	resolver, err := underlay.DialerFrom(ctx, underlay.DNSBootstrap)
	if err != nil {
		return nil, err
	}
	s, _ := module.Decode(n.Options.Data)
	p := c.Payload.(access.UsernamePasswordPayload)
	transport := pb.TransportProtocol_TCP
	if s.Transport == "udp" {
		transport = pb.TransportProtocol_UDP
	}
	endpoint := &pb.ServerEndpoint{PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(n.Endpoint.Port)), Protocol: transport.Enum()}}}
	if net.ParseIP(n.Endpoint.Host) != nil {
		endpoint.IpAddress = proto.String(n.Endpoint.Host)
	} else {
		endpoint.DomainName = proto.String(n.Endpoint.Host)
	}
	level := pb.MultiplexingLevel(pb.MultiplexingLevel_value["MULTIPLEXING_"+strings.ToUpper(s.Multiplex)])
	d := &mieruDialer{client: api.NewClient(), owner: clientio.New(), endpoint: n.Endpoint, protected: protected, resolver: resolver}
	profile := &pb.ClientProfile{ProfileName: proto.String("managed"), User: &pb.User{Name: proto.String(p.Username.Reveal()), Password: proto.String(p.Password.Reveal())}, Servers: []*pb.ServerEndpoint{endpoint}, Mtu: proto.Int32(int32(s.MTU)), Multiplexing: &pb.MultiplexingConfig{Level: level.Enum()}, HandshakeMode: pb.HandshakeMode_HANDSHAKE_NO_WAIT.Enum()}
	if err := d.client.Store(&api.ClientConfig{Profile: profile, Dialer: d, PacketDialer: d, Resolver: d.resolver}); err != nil {
		d.owner.Close()
		return nil, identity.Err(identity.Unavailable, "Mieru client construction failed")
	}
	if err := d.client.Start(); err != nil {
		d.owner.Close()
		_ = d.client.Stop()
		return nil, identity.Err(identity.Unavailable, "Mieru client start failed")
	}
	return &mieruOutbound{d}, nil
}

// The injected underlay dialer and logical outbound are different types: their
// DialContext contracts have different arguments and both use the same owner.
type mieruDialer struct {
	protected, resolver *underlay.Dialer
	client              api.Client
	owner               *clientio.Owner
	endpoint            access.Endpoint
}

func (d *mieruDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	joined, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	// The SDK resolves a server domain to one address before invoking Dialer.
	// Preserve the owned canonical endpoint here so net.Dialer can perform its
	// normal IPv4/IPv6 connection selection on each TCP underlay, including Windows.
	if net.ParseIP(d.endpoint.Host) == nil {
		address = net.JoinHostPort(d.endpoint.Host, strconv.Itoa(int(d.endpoint.Port)))
	}
	c, err := d.protected.DialContext(joined, network, address)
	if err != nil {
		return nil, err
	}
	return d.owner.Conn(c)
}
func (d *mieruDialer) ListenPacket(ctx context.Context, network, laddr, raddr string) (net.PacketConn, error) {
	joined, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, err := d.protected.ListenPacket(joined, network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	return d.owner.Packet(c)
}

type mieruOutbound struct{ d *mieruDialer }

func (o *mieruOutbound) dial(ctx context.Context, network string, e access.Endpoint) (net.Conn, error) {
	joined, done, err := o.d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	addr := model.NetAddrSpec{Net: network, AddrSpec: model.AddrSpec{Port: int(e.Port)}}
	if ip := net.ParseIP(e.Host); ip != nil {
		addr.IP = ip
	} else {
		addr.FQDN = e.Host
	}
	c, err := o.d.client.DialContext(joined, addr)
	if err != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, err
	}
	return o.d.owner.Conn(c)
}
func (o *mieruOutbound) DialContext(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	return o.dial(ctx, "tcp", e)
}
func (o *mieruOutbound) ListenPacket(ctx context.Context, e access.Endpoint) (net.PacketConn, error) {
	ctx, done, err := o.d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	// The official UDPAssociateWrapper receive contract accepts IP headers only,
	// including on the embedded server. Resolve this UDP flow locally, retaining
	// the canonical target/node domain and using the official framing unchanged.
	address, err := ac.ResolveUDPAddr(ctx, o.d.resolver, "udp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))))
	if err != nil {
		return nil, err
	}
	c, err := o.dial(ctx, "udp", e)
	if err != nil {
		return nil, err
	}
	p := newMieruPacket(ac.NewUDPAssociateWrapper(ac.NewPacketOverStreamTunnel(c)), address)
	// Register the complete session owner too: adapter shutdown must join its
	// bounded writer even if it closes the underlying owned Conn first.
	return o.d.owner.Packet(p)
}

type mieruPacket struct {
	net.PacketConn
	target *net.UDPAddr
	writes *packetio.Queue
	writer *packetio.Writer
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func newMieruPacket(pc net.PacketConn, target *net.UDPAddr) *mieruPacket {
	parent, cancel := context.WithCancel(context.Background())
	destination := *target
	destination.IP = append(net.IP(nil), target.IP...)
	p := &mieruPacket{PacketConn: pc, target: &destination, cancel: cancel}
	// The official SDK snapshots the deadline when writeChunk begins. Only its
	// private session can interrupt that call; it must not own the child's live
	// deadline. One session-owned worker may finish one committed owned frame.
	p.writer = packetio.NewAddressWriter(parent, func(b []byte, a net.Addr) error {
		_, err := pc.WriteTo(b, a)
		return err
	})
	p.writes = packetio.New(parent, nil, func(ctx context.Context, b []byte, a net.Addr) error {
		return p.writer.SendTo(ctx, b, a)
	})
	return p
}

func (p *mieruPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.writes.WriteTo(b, p.target)
}

func (p *mieruPacket) Close() error {
	p.once.Do(func() {
		_ = p.writes.Close()
		p.cancel()
		p.err = p.PacketConn.Close()
		p.writer.Wait()
	})
	return p.err
}
func (p *mieruPacket) SetWriteDeadline(t time.Time) error { return p.writes.SetWriteDeadline(t) }
func (p *mieruPacket) SetDeadline(t time.Time) error {
	if err := p.SetReadDeadline(t); err != nil {
		return err
	}
	return p.SetWriteDeadline(t)
}
func (o *mieruOutbound) Close() error { o.d.owner.Close(); return o.d.client.Stop() }
