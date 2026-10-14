package streamtransport

import (
	"context"
	"net"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/streamtransport/mkcp"
)

// ListenCarrier atomically acquires the transport's actual listening socket.
// Stream protocols consume the same listener interface regardless of carrier.
func ListenCarrier(ctx context.Context, address string, c cfg.Config) (net.Listener, error) {
	if err := c.ValidateServer(); err != nil {
		return nil, err
	}
	lc := net.ListenConfig{}
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
