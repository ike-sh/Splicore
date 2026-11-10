package underlay

import (
	"context"
	"net"

	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
)

// ownResolver bounds the physical work of one private resolver lookup. The Go
// resolver may return on cancellation before its internal query goroutines exit.
func ownResolver(r *net.Resolver) *clientio.Owner {
	owner := clientio.New()
	dial := r.Dial
	r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, done, err := owner.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer done()
		raw, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		conn, err := owner.Conn(raw)
		if err != nil {
			return nil, err
		}
		if packet, ok := raw.(net.PacketConn); ok {
			// Preserve PacketConn so net.Resolver uses DNS datagram framing.
			return &resolverPacketConn{Conn: conn, packet: packet}, nil
		}
		return conn, nil
	}
	return owner
}

type resolverPacketConn struct {
	net.Conn
	packet net.PacketConn
}

func (c *resolverPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.packet.ReadFrom(b)
}
func (c *resolverPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	return c.packet.WriteTo(b, a)
}
