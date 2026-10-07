package backend

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/trojan/wire"
)

// Packet owns one authenticated stream. No read pump, detached write goroutine,
// multiplexing or per-destination registry is created by this adapter.
type Packet struct {
	c          net.Conn
	queue      *packetio.Queue
	rmu, mu    sync.Mutex
	closed     bool
	writes     sync.WaitGroup
	once       sync.Once
	closeOnce  sync.Once
	stopParent func() bool
	parentDone chan struct{}
}

func NewPacket(ctx context.Context, c net.Conn) *Packet {
	p := &Packet{c: c, parentDone: make(chan struct{})}
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
		_ = p.c.Close()
	})
}
func (p *Packet) send(ctx context.Context, b []byte, a net.Addr) error {
	dst, err := netaddr.From(a)
	if err != nil {
		return wire.ErrFrame
	}
	frame, err := wire.EncodePacket(b, dst)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return net.ErrClosed
	}
	p.writes.Add(1)
	p.mu.Unlock()
	defer p.writes.Done()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		if p.c.SetWriteDeadline(time.Now()) != nil {
			p.retire()
		}
		close(interrupted)
	})
	n, err := p.c.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if !stop() {
		<-interrupted
		if err == nil {
			// Join before resetting the temporary interruption deadline; the
			// queue remains the authority for the next operation's live timer.
			if p.c.SetWriteDeadline(time.Time{}) != nil {
				p.retire()
			}
		}
	}
	// Go TLS also memoizes write errors. Terminalizing every failed admitted
	// write avoids pretending a zero-byte TLS timeout restored a usable stream.
	if err != nil {
		p.retire()
		return err
	}
	return nil
}
func (p *Packet) ReadFrom(b []byte) (int, net.Addr, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return 0, nil, net.ErrClosed
	}
	reader := &packetReader{Reader: p.c}
	data, dst, err := wire.ReadPacket(reader)
	if err != nil {
		p.retire()
		if reader.err != nil {
			return 0, nil, reader.err
		}
		return 0, nil, err
	}
	if len(b) < len(data) {
		return 0, netaddr.UDP(dst), io.ErrShortBuffer
	}
	return copy(b, data), netaddr.UDP(dst), nil
}
func (p *Packet) WriteTo(b []byte, a net.Addr) (int, error) { return p.queue.WriteTo(b, a) }
func (p *Packet) Close() error {
	p.closeOnce.Do(func() {
		p.retire()
		if !p.stopParent() {
			<-p.parentDone
		}
		p.writes.Wait()
		p.rmu.Lock()
		p.rmu.Unlock()
	})
	return nil
}

// Preserve socket EOF/deadline semantics while keeping malformed frame errors
// generic. A failed read retires this association because parsing consumed an
// unknown prefix of its stream.
type packetReader struct {
	io.Reader
	err error
}

func (r *packetReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if err != nil {
		r.err = err
	}
	return n, err
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
