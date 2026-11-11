package native

import (
	"context"
	"net"
	"net/netip"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	shared "github.com/ike-sh/Splicore/internal/splicore/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

// Capture the retained Core DNS generation at Build. A managed lookup failure
// is terminal: neither HTTP nor the QUIC library receives a hostname to resolve.
func nativeManagedDial(build context.Context, dial shared.DialFunc) shared.DialFunc {
	lookup := underlay.BootstrapFrom(build)
	if lookup == nil {
		return dial
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		if _, e = netip.ParseAddr(host); e == nil {
			return dial(ctx, network, address)
		}
		ips, e := lookup(ctx, host)
		if e != nil {
			return nil, e
		}
		if len(ips) == 0 {
			return nil, net.InvalidAddrError("empty managed transport resolution")
		}
		var last error
		for _, ip := range ips {
			if !ip.IsValid() {
				return nil, net.InvalidAddrError("invalid managed transport address")
			}
			c, e := dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if e == nil {
				return c, nil
			}
			last = e
		}
		return nil, last
	}
}

func nativePacketSocket(build context.Context, endpoint access.Endpoint) (shared.PacketSocket, error) {
	lookup := underlay.BootstrapFrom(build)
	if lookup == nil {
		return clientconfig.PacketSocket(build, endpoint)
	}
	// Validate capabilities before publishing the outbound even though DNS is lazy.
	if _, e := clientconfig.PacketSocket(build, endpoint); e != nil {
		return nil, e
	}
	return func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		peer := endpoint
		if _, e := netip.ParseAddr(peer.Host); e != nil {
			ips, e := lookup(ctx, peer.Host)
			if e != nil {
				return nil, nil, e
			}
			if len(ips) == 0 {
				return nil, nil, net.InvalidAddrError("empty managed transport resolution")
			}
			ip := ips[0]
			for _, v := range ips {
				if v.Unmap().Is4() {
					ip = v
					break
				}
			}
			if !ip.IsValid() {
				return nil, nil, net.InvalidAddrError("invalid managed transport address")
			}
			peer.Host = ip.Unmap().String()
		}
		socket, e := clientconfig.PacketSocket(build, peer)
		if e != nil {
			return nil, nil, e
		}
		return socket(ctx)
	}, nil
}
