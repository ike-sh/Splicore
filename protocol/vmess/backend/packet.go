package backend

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/vmess/wire"
)

// Packet binds one canonical command-2 stream to its request destination. The
// shared client flow/relay registries own destination selection and retirement.
type Packet struct {
	c               *Conn
	destination     access.Endpoint
	queue           *packetio.Queue
	mu              sync.Mutex
	closed          bool
	writes          sync.WaitGroup
	once, closeOnce sync.Once
	stopParent      func() bool
	parentDone      chan struct{}
}

func NewPacket(ctx context.Context, c *Conn, dst access.Endpoint) *Packet {
	p := &Packet{c: c, destination: dst, parentDone: make(chan struct{})}
	p.queue = packetio.New(ctx, c.LocalAddr(), p.send)
	p.stopParent = context.AfterFunc(ctx, func() { p.retire(); close(p.parentDone) })
	return p
}
func (p *Packet) retire() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		_ = p.queue.Close()
		p.c.retire()
	})
}
func (p *Packet) send(ctx context.Context, b []byte, a net.Addr) error {
	dst, err := netaddr.From(a)
	if err != nil || dst.Port != p.destination.Port {
		return wire.ErrFrame
	}
	if dst != p.destination {
		boundKind, _ := access.ParseHost(p.destination.Host)
		replyKind, _ := access.ParseHost(dst.Host)
		// The server's shared relay replies from its connected, resolved UDP
		// target socket. That numeric address is metadata for the same bound
		// destination, and does not select another VMess destination.
		if !p.c.server || boundKind != access.DNS || replyKind == access.DNS {
			return wire.ErrFrame
		}
	}
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { p.c.retire(); close(finished) })
	err = p.c.writePacket(b)
	if !stop() {
		<-finished
	}
	return err
}
func (p *Packet) ReadFrom(b []byte) (int, net.Addr, error) {
	v, err := p.c.readPacket()
	if err != nil {
		return 0, nil, err
	}
	if len(b) < len(v) {
		return 0, netaddr.UDP(p.destination), io.ErrShortBuffer
	}
	return copy(b, v), netaddr.UDP(p.destination), nil
}
func (p *Packet) WriteTo(b []byte, a net.Addr) (int, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	p.writes.Add(1)
	p.mu.Unlock()
	defer p.writes.Done()
	return p.queue.WriteTo(b, a)
}
func (p *Packet) Close() error {
	p.closeOnce.Do(func() {
		p.retire()
		if !p.stopParent() {
			<-p.parentDone
		}
		p.writes.Wait()
		_ = p.c.Close()
	})
	return nil
}
func (p *Packet) LocalAddr() net.Addr                { return p.c.LocalAddr() }
func (p *Packet) SetReadDeadline(t time.Time) error  { return p.c.SetReadDeadline(t) }
func (p *Packet) SetWriteDeadline(t time.Time) error { return p.queue.SetWriteDeadline(t) }
func (p *Packet) SetDeadline(t time.Time) error {
	if err := p.SetReadDeadline(t); err != nil {
		return err
	}
	return p.SetWriteDeadline(t)
}
