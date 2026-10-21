package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trusttunnel"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/session"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
)

type TrustTunnelOutboundFactory struct{}

func (TrustTunnelOutboundFactory) Capability() ports.OutboundCapability {
	c := clientconfig.Capability("trusttunnel", true, session.H3Enabled(), false)
	c.UDPDomainResolution = "local"
	return c
}
func (TrustTunnelOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return module.ValidateClient(n, c)
}
func (f TrustTunnelOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if e := f.Validate(n, c); e != nil {
		return nil, e
	}
	o, _ := module.DecodeClient(n.Options.Data)
	tc, e := clientconfig.TLS(n.Security.TLS, n.Endpoint.Host)
	if e != nil {
		return nil, e
	}
	configureTrustTunnelTLS(tc, o)
	dialer, e := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if e != nil {
		return nil, e
	}
	resolver, e := underlay.DialerFrom(ctx, underlay.DNSBootstrap)
	if e != nil {
		return nil, e
	}
	addresses := o.Addresses
	if len(addresses) == 0 {
		addresses = []string{module.Address(n.Endpoint)}
	}
	for i, a := range addresses {
		canonical, err := wire.Authority(a)
		if err != nil {
			return nil, identity.Err(identity.Invalid, "invalid TrustTunnel endpoint")
		}
		addresses[i] = canonical
	}
	sockets := map[string]func(context.Context) (net.PacketConn, net.Addr, error){}
	if o.Mode != "http2" {
		for _, address := range addresses {
			host, port, _ := net.SplitHostPort(address)
			number, _ := strconv.ParseUint(port, 10, 16)
			factory, e := clientconfig.PacketSocket(ctx, access.Endpoint{Host: host, Port: uint16(number)})
			if e != nil {
				return nil, e
			}
			sockets[address] = factory
		}
	}
	connect, _ := module.Duration(o.ConnectTimeout, "30s")
	health, _ := module.Duration(o.HealthTimeout, "7s")
	fallback, _ := module.Duration(o.FallbackDelay, "1s")
	idle, _ := module.Duration(o.IdleTimeout, "10m")
	udpIdle, _ := module.Duration(o.UDPIdleTimeout, "120s")
	p := c.Payload.(access.UsernamePasswordPayload)
	cfg := session.ClientConfig{Mode: o.Mode, Addresses: addresses, TLS: tc, Username: p.Username.Reveal(), Password: p.Password.Reveal(), UserAgent: o.UserAgent, DialTCP: dialer.DialContext, ConnectTimeout: connect, HealthTimeout: health, FallbackDelay: fallback, SessionIdleTimeout: idle, UDPIdleTimeout: udpIdle, MaxStreams: o.MaxStreams, MaxFlows: o.MaxFlows, PacketSocket: func(ctx context.Context, a string) (net.PacketConn, net.Addr, error) {
		factory := sockets[a]
		if factory == nil {
			return nil, nil, identity.Err(identity.Invalid, "unrecognized TrustTunnel endpoint")
		}
		return factory(ctx)
	}}
	transport, e := session.NewClient(cfg)
	if e != nil {
		return nil, e
	}
	return &trustTunnelDialer{client: transport, owner: clientio.New(), resolver: resolver, disableIPv6: o.DisableIPv6}, nil
}

// A custom SNI changes only ClientHello. Verification still uses the profile's
// original hostname and chain. VerifyConnection also runs for resumed sessions.
func configureTrustTunnelTLS(tc *tls.Config, o module.ClientOptions) {
	if o.CustomSNI == "" {
		tc.InsecureSkipVerify = o.Insecure
		return
	}
	name := tc.ServerName
	tc.ServerName = o.CustomSNI
	tc.InsecureSkipVerify = true
	if !o.Insecure {
		tc.VerifyConnection = func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return identity.Err(identity.Invalid, "TrustTunnel certificate missing")
			}
			intermediates := x509.NewCertPool()
			for _, c := range s.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			_, e := s.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: tc.RootCAs, Intermediates: intermediates, DNSName: name})
			return e
		}
	}
}

type trustTunnelDialer struct {
	client      *session.Client
	owner       *clientio.Owner
	resolver    *underlay.Dialer
	disableIPv6 bool
}

func (d *trustTunnelDialer) SupportsNetwork(n string) bool { return n == "tcp" || n == "udp" }
func (d *trustTunnelDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	if dst.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "invalid TrustTunnel destination")
	}
	if ip, e := netip.ParseAddr(dst.Host); e == nil && ip.Unmap().Is6() && d.disableIPv6 {
		return nil, identity.Err(identity.Unavailable, "TrustTunnel IPv6 disabled")
	}
	ctx, done, e := d.owner.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	n, e := d.client.Open(ctx, module.Address(dst))
	if e != nil {
		return nil, e
	}
	return d.owner.Conn(n)
}
func (d *trustTunnelDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	if dst.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "invalid TrustTunnel UDP destination")
	}
	ctx, done, e := d.owner.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	ip, e := netip.ParseAddr(dst.Host)
	if e != nil {
		ips, e := d.resolver.LookupNetIP(ctx, "ip", dst.Host)
		if e != nil {
			return nil, e
		}
		for _, candidate := range ips {
			candidate = candidate.Unmap()
			if !d.disableIPv6 || candidate.Is4() {
				ip = candidate
				break
			}
		}
		if !ip.IsValid() {
			return nil, identity.Err(identity.Unavailable, "TrustTunnel UDP resolution unavailable")
		}
	}
	ip = ip.Unmap()
	if ip.Is6() && d.disableIPv6 {
		return nil, identity.Err(identity.Unavailable, "TrustTunnel IPv6 disabled")
	}
	p, e := d.client.OpenPacket(ctx, netip.AddrPortFrom(ip, dst.Port))
	if e != nil {
		return nil, e
	}
	return d.owner.Packet(&trustTunnelResolvedPacket{PacketConn: p, original: dst, resolved: net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, dst.Port))})
}

// A semantic hostname destination is resolved once by the Core resolver. The
// returned association accepts only that original destination (or its pinned
// numeric address), preserving the routing decision on later WriteTo calls.
type trustTunnelResolvedPacket struct {
	net.PacketConn
	original access.Endpoint
	resolved *net.UDPAddr
}

func (p *trustTunnelResolvedPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	dst, e := netaddr.From(a)
	if e != nil {
		return 0, identity.Err(identity.Invalid, "invalid TrustTunnel UDP destination")
	}
	numeric := dst.Host == p.resolved.IP.String() && dst.Port == uint16(p.resolved.Port)
	original := strings.EqualFold(dst.Host, p.original.Host) && dst.Port == p.original.Port
	if !numeric && !original {
		return 0, identity.Err(identity.Invalid, "TrustTunnel UDP association destination changed")
	}
	return p.PacketConn.WriteTo(b, p.resolved)
}
func (d *trustTunnelDialer) Close() error { d.owner.Close(); return d.client.Close() }
