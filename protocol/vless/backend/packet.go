package backend

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/vless/wire"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Packets owns the stream reader and all child UDP sessions. Parent cancel
// interrupts sockets, then waits for each relay before releasing the stream.
func Packets(ctx context.Context, c net.Conn, request wire.Request, handle func(context.Context, net.PacketConn) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	var registry packetRegistry
	writer := newPacketWriter(ctx, c, cancel)
	defer func() {
		writer.retire()
		registry.close()
		workers.Wait()
		<-writer.done
	}()
	for {
		var f wire.Frame
		if request.Command == wire.UDP {
			var size [2]byte
			if _, err := io.ReadFull(c, size[:]); err != nil {
				return err
			}
			n := int(binary.BigEndian.Uint16(size[:]))
			if n > wire.MaxPayload {
				return wire.ErrFrame
			}
			f = wire.Frame{Status: 2, Options: 1, Network: 2, Destination: request.Destination, Payload: make([]byte, n)}
			if _, err := io.ReadFull(c, f.Payload); err != nil {
				return err
			}
		} else {
			var err error
			f, err = wire.ReadFrame(c)
			if err != nil {
				return err
			}
		}
		if f.Status == 4 {
			continue
		}
		if f.Status == 3 {
			if p := registry.lookup(f.Session); p != nil {
				_ = p.Close()
			}
			continue
		}
		if f.Network != 0 && f.Network != 2 {
			return wire.ErrFrame
		}
		session := f.Session
		p, dst, created, err := registry.register(session, f.Destination, func() *packetio.Queue {
			return packetio.New(ctx, c.LocalAddr(), func(writeCtx context.Context, payload []byte, address net.Addr) error {
				dst, err := netaddr.From(address)
				if err != nil {
					return err
				}
				if request.Command == wire.UDP {
					if len(payload) > wire.MaxPayload {
						return wire.ErrFrame
					}
					b := binary.BigEndian.AppendUint16(nil, uint16(len(payload)))
					return writer.send(writeCtx, append(b, payload...))
				}
				encoded, err := wire.EncodeFrame(wire.Frame{Session: session, Status: 2, Network: 2, Destination: dst, Payload: payload})
				if err != nil {
					return err
				}
				return writer.send(writeCtx, encoded)
			})
		})
		if err != nil {
			return err
		}
		if created {
			workers.Add(1)
			go func(p *packetAssociation) { defer workers.Done(); defer p.Close(); _ = handle(p.Context(), p) }(p)
		}
		if f.Options&1 != 0 {
			p.Deliver(f.Payload, netaddr.UDP(dst))
		}
	}
}

type ClientPacket struct {
	net.Conn
	destination access.Endpoint
	rmu, wmu    sync.Mutex
	started     bool
	writeErr    error // guarded by wmu
	closed      atomic.Bool
	closeOnce   sync.Once
	closeErr    error
}

func (p *ClientPacket) LocalAddr() net.Addr { return p.Conn.LocalAddr() }
func (p *ClientPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	for {
		f, err := wire.ReadFrame(p.Conn)
		if err != nil {
			return 0, nil, err
		}
		if f.Status == 3 {
			return 0, nil, io.EOF
		}
		if f.Status == 4 || f.Options&1 == 0 {
			continue
		}
		if f.Session != 0 || f.Status != 2 {
			return 0, nil, wire.ErrFrame
		}
		dst := f.Destination
		if dst == (access.Endpoint{}) {
			dst = p.destination
		}
		if len(b) < len(f.Payload) {
			return 0, nil, io.ErrShortBuffer
		}
		return copy(b, f.Payload), netaddr.UDP(dst), nil
	}
}
func (p *ClientPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if p.writeErr != nil {
		return 0, p.writeErr
	}
	if p.closed.Load() {
		return 0, net.ErrClosed
	}
	status := byte(2)
	if !p.started {
		status = 1
	}
	frame, err := wire.EncodeFrame(wire.Frame{Status: status, Network: 2, Destination: p.destination, Payload: b})
	if err != nil {
		return 0, err
	}
	n, err := p.Conn.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		if n > 0 {
			p.writeErr = errors.Join(net.ErrClosed, err)
			_ = p.Close()
		}
		return 0, err
	}
	p.started = true
	return len(b), nil
}
func (p *ClientPacket) Close() error {
	p.closed.Store(true)
	p.closeOnce.Do(func() { p.closeErr = p.Conn.Close() })
	return p.closeErr
}
func NewClientPacket(c net.Conn, dst access.Endpoint) net.PacketConn {
	return &ClientPacket{Conn: c, destination: dst}
}
func (p *ClientPacket) SetDeadline(t time.Time) error { return p.Conn.SetDeadline(t) }
