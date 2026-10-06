package clientconfig

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"net"
	"net/netip"
)

// PacketSocket lazily creates a protected numeric UDP socket for one private
// QUIC flow. Dual-stack proxy names preserve managed IPv4 preference.
func PacketSocket(ctx context.Context, endpoint access.Endpoint) (func(context.Context) (net.PacketConn, net.Addr, error), error) {
	protected, err := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if err != nil {
		return nil, err
	}
	resolver, err := underlay.DialerFrom(ctx, underlay.DNSBootstrap)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		ip, err := netip.ParseAddr(endpoint.Host)
		if err != nil {
			ips, err := resolver.LookupNetIP(ctx, "ip", endpoint.Host)
			if err != nil {
				return nil, nil, err
			}
			if len(ips) == 0 {
				return nil, nil, net.InvalidAddrError("empty QUIC endpoint resolution")
			}
			ip = ips[0]
			for _, candidate := range ips {
				if candidate.Unmap().Is4() {
					ip = candidate
					break
				}
			}
		}
		ip = ip.Unmap()
		address := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, endpoint.Port))
		network, local := "udp4", "0.0.0.0:0"
		if ip.Is6() {
			network, local = "udp6", "[::]:0"
		}
		packet, err := protected.ListenPacket(ctx, network, local, address.String())
		return packet, address, err
	}, nil
}
