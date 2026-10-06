package backend

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/hysteria2/wire"
)

// Packet owns its child queue, cancellation and live deadlines. The parent
// owns the transport writer; closing this child never closes sibling transport.
type Packet struct {
	*packetio.Queue
	ctx     context.Context
	session uint32
	packet  atomic.Uint32
}

func newPacket(ctx context.Context, local net.Addr, session uint32, send func(context.Context, []byte) error) *Packet {
	p := &Packet{session: session}
	p.Queue = packetio.New(ctx, local, func(writeCtx context.Context, b []byte, a net.Addr) error {
		dst, err := netaddr.From(a)
		if err != nil {
			return err
		}
		frames, err := wire.Fragments(session, uint16(p.packet.Add(1)), dst, b)
		if err != nil {
			return err
		}
		for _, frame := range frames {
			if err := send(writeCtx, frame); err != nil {
				return err
			}
		}
		return nil
	})
	p.ctx = p.Context()
	return p
}

func (p *Packet) deliver(d wire.Datagram) {
	// Queue copies payload before transfer, independent of assembly scratch.
	p.Deliver(d.Payload, netaddr.UDP(d.Destination))
}

// DefaultPacket confines a managed client flow to its committed destination.
// Server packets retain the destination on each independently owned datagram.
type DefaultPacket struct {
	net.PacketConn
	Destination access.Endpoint
}

func (p *DefaultPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.PacketConn.WriteTo(b, netaddr.UDP(p.Destination))
}
