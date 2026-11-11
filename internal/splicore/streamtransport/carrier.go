package streamtransport

import (
	"context"
	"net"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/streamtransport/mkcp"
)

// ListenCarrier atomically acquires the transport's actual listening socket.
// Stream protocols consume the same listener interface regardless of carrier.
func ListenCarrier(ctx context.Context, address string, c cfg.Config, alpn ...[]string) (net.Listener, error) {
	if err := c.ValidateServer(); err != nil {
		return nil, err
	}
	lc := net.ListenConfig{}
	if c.Type() == "quic-stream" || len(alpn) > 0 && c.XHTTPH3(alpn[0]) {
		p, err := lc.ListenPacket(ctx, "udp", address)
		if err != nil {
			return nil, err
		}
		return &quicCarrier{packet: p}, nil
	}
	if c.Type() != "mkcp" {
		return lc.Listen(ctx, "tcp", address)
	}
	packet, err := lc.ListenPacket(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	listener, err := mkcp.NewListener(packet, c.MKCPSettings())
	if err != nil {
		packet.Close()
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// quicCarrier reserves UDP atomically; TLS composition starts QUIC later.
type quicCarrier struct{ packet net.PacketConn }

func (c *quicCarrier) Accept() (net.Conn, error) { return nil, errNativeConfig }
func (c *quicCarrier) Close() error              { return c.packet.Close() }
func (c *quicCarrier) Addr() net.Addr            { return c.packet.LocalAddr() }
