package native

import (
	"context"
	api "github.com/enfein/mieru/v3/apis/client"
	ac "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/engine/clientio"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/mieru"
	"google.golang.org/protobuf/proto"
	"net"
	"strconv"
	"strings"
)

type MieruOutboundFactory struct{}

func (MieruOutboundFactory) Capability() ports.OutboundCapability {
	c := clientCapability("mieru", false, false, false)
	c.UDPDomainResolution = "local"
	return c
}
func (MieruOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if err := clientOwnership(n, c); err != nil {
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
func (f MieruOutboundFactory) Build(_ context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if err := f.Validate(n, c); err != nil {
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
	d := &mieruDialer{client: api.NewClient(), owner: clientio.New(), endpoint: n.Endpoint}
	profile := &pb.ClientProfile{ProfileName: proto.String("managed"), User: &pb.User{Name: proto.String(p.Username.Reveal()), Password: proto.String(p.Password.Reveal())}, Servers: []*pb.ServerEndpoint{endpoint}, Mtu: proto.Int32(int32(s.MTU)), Multiplexing: &pb.MultiplexingConfig{Level: level.Enum()}, HandshakeMode: pb.HandshakeMode_HANDSHAKE_NO_WAIT.Enum()}
	if err := d.client.Store(&api.ClientConfig{Profile: profile, Dialer: d, PacketDialer: d, Resolver: net.DefaultResolver}); err != nil {
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
	client   api.Client
	owner    *clientio.Owner
	endpoint access.Endpoint
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
	c, err := (&net.Dialer{}).DialContext(joined, network, address)
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
	c, err := (&net.ListenConfig{}).ListenPacket(joined, network, laddr)
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
	address, err := ac.ResolveUDPAddr(ctx, net.DefaultResolver, "udp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))))
	if err != nil {
		return nil, err
	}
	c, err := o.dial(ctx, "udp", e)
	if err != nil {
		return nil, err
	}
	return &mieruPacket{PacketConn: ac.NewUDPAssociateWrapper(ac.NewPacketOverStreamTunnel(c)), target: address}, nil
}

type mieruPacket struct {
	net.PacketConn
	target *net.UDPAddr
}

func (p *mieruPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.PacketConn.WriteTo(b, p.target)
}
func (o *mieruOutbound) Close() error { o.d.owner.Close(); return o.d.client.Stop() }
