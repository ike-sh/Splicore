package backend

import (
	"context"
	"errors"
	"github.com/apernet/quic-go"
	ht "github.com/ike-sh/Splicore/internal/splicore/streamtransport/hysteria"
	"net"
	"sync"
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
	ctx        context.Context
	session    uint32
	packet     atomic.Uint32
	touch      func()
	afterClose func()
	closeOnce  sync.Once
}

func (p *Packet) Close() error {
	p.closeOnce.Do(func() {
		_ = p.Queue.Close()
		if p.afterClose != nil {
			p.afterClose()
		}
	})
	return nil
}

func newPacket(ctx context.Context, local net.Addr, session uint32, send func(context.Context, []byte) error) *Packet {
	return newPacketLimit(ctx, local, session, send, nil)
}
func newCarrierPacket(c *ht.Connection, session uint32) *Packet {
	var limit atomic.Int64
	limit.Store(1197)
	return newPacketLimit(c.Context(), c.QUIC.LocalAddr(), session, c.SendDatagram, &limit)
}
func newPacketLimit(ctx context.Context, local net.Addr, session uint32, send func(context.Context, []byte) error, limit *atomic.Int64) *Packet {
	p := &Packet{session: session}
	p.Queue = packetio.New(ctx, local, func(writeCtx context.Context, b []byte, a net.Addr) error {
		dst, err := netaddr.From(a)
		if err != nil {
			return err
		}
		maxSize := 1197
		if limit != nil {
			maxSize = int(limit.Load())
		}
		frames, err := wire.FragmentsAt(session, uint16(p.packet.Add(1)), dst, b, maxSize)
		if err != nil {
			return err
		}
		for _, frame := range frames {
			if err := send(writeCtx, frame); err != nil {
				var size *quic.DatagramTooLargeError
				if limit != nil && errors.As(err, &size) && size.MaxDatagramPayloadSize > 0 && size.MaxDatagramPayloadSize < int64(maxSize) {
					limit.Store(size.MaxDatagramPayloadSize)
					// A new packet ID prevents partial old fragments mixing with
					// the replacement's different fragment count. One adaptation,
					// never retransmission of a lost application datagram.
					fresh, e := wire.FragmentsAt(session, uint16(p.packet.Add(1)), dst, b, int(size.MaxDatagramPayloadSize))
					if e != nil {
						return e
					}
					for _, f := range fresh {
						if e = send(writeCtx, f); e != nil {
							return e
						}
					}
					if p.touch != nil {
						p.touch()
					}
					return nil
				}
				return err
			}
		}
		if p.touch != nil {
			p.touch()
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
