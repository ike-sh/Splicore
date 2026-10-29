package native

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
)

// Selection is lazy: a packet flow with a valid Initial uses a dedicated UDP
// socket; other traffic keeps UDP over TCP. No user payload is replayed across
// paths after selection. Close cancels admission and joins active writers.
type snellV5Packet struct {
	mu                          sync.Mutex
	dialer                      *snellDialer
	dst                         access.Endpoint
	ctx                         context.Context
	cancel                      context.CancelFunc
	child                       net.PacketConn
	ready, changed              chan struct{}
	gate                        chan struct{}
	readDeadline, writeDeadline time.Time
	closed                      bool
	writers                     sync.WaitGroup
	once                        sync.Once
	release                     func()
}

func newSnellV5Packet(d *snellDialer, dst access.Endpoint) (net.PacketConn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &snellV5Packet{dialer: d, dst: dst, ctx: ctx, cancel: cancel, ready: make(chan struct{}), changed: make(chan struct{}), gate: make(chan struct{}, 1)}
	// Track and Close can overlap; registration is complete before publication.
	p.mu.Lock()
	release, err := d.owner.Track(p)
	if err != nil {
		p.mu.Unlock()
		cancel()
		return nil, err
	}
	p.release = release
	p.mu.Unlock()
	return p, nil
}

func (p *snellV5Packet) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	p.writers.Add(1)
	p.mu.Unlock()
	defer p.writers.Done()
	select {
	case p.gate <- struct{}{}:
	case <-p.ctx.Done():
		return 0, net.ErrClosed
	}
	defer func() { <-p.gate }()
	p.mu.Lock()
	child, deadline, closed := p.child, p.writeDeadline, p.closed
	p.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}
	if child == nil {
		ctx, done, err := p.dialer.owner.Begin(p.ctx)
		if err != nil {
			return 0, err
		}
		admission, cancel := p.admission(ctx)
		if wire.QUICInitial(b) {
			var raw net.Conn
			raw, err = p.dialer.protected.DialContext(admission, "udp", net.JoinHostPort(p.dialer.endpoint.Host, portString(p.dialer.endpoint.Port)))
			if err == nil {
				child = &snellRawPacket{Conn: raw, key: p.dialer.key, dst: p.dst}
			}
		} else {
			child, err = p.dialer.listenPacketTCP(admission, p.dst)
		}
		cancel()
		done()
		if err != nil {
			return 0, err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = child.Close()
			return 0, net.ErrClosed
		}
		_ = child.SetReadDeadline(p.readDeadline)
		_ = child.SetWriteDeadline(p.writeDeadline)
		p.child = child
		close(p.ready)
		p.mu.Unlock()
	}
	return child.WriteTo(b, netaddr.UDP(p.dst))
}

// Deadline changes also interrupt an admission already waiting on DNS or TCP.
func (p *snellV5Packet) admission(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			p.mu.Lock()
			deadline, changed := p.writeDeadline, p.changed
			p.mu.Unlock()
			var timer *time.Timer
			var expired <-chan time.Time
			if !deadline.IsZero() {
				timer = time.NewTimer(time.Until(deadline))
				expired = timer.C
			}
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case <-expired:
				cancel()
				return
			case <-changed:
				if timer != nil {
					timer.Stop()
				}
			}
		}
	}()
	return ctx, func() { cancel(); <-done }
}

func (p *snellV5Packet) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		child, deadline, changed, closed := p.child, p.readDeadline, p.changed, p.closed
		p.mu.Unlock()
		if closed {
			return 0, nil, net.ErrClosed
		}
		if child != nil {
			return child.ReadFrom(b)
		}
		if !deadline.IsZero() && !deadline.After(time.Now()) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		var expired <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		select {
		case <-p.ready:
		case <-p.ctx.Done():
		case <-changed:
		case <-expired:
			return 0, nil, os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (p *snellV5Packet) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		child := p.child
		p.mu.Unlock()
		p.cancel()
		if child != nil {
			_ = child.Close()
		}
		p.writers.Wait()
		if p.release != nil {
			p.release()
		}
	})
	return nil
}

func (p *snellV5Packet) LocalAddr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.child != nil {
		return p.child.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (p *snellV5Packet) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline, p.writeDeadline = t, t
	close(p.changed)
	p.changed = make(chan struct{})
	if p.child != nil {
		return p.child.SetDeadline(t)
	}
	return nil
}

func (p *snellV5Packet) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	if p.child != nil {
		return p.child.SetReadDeadline(t)
	}
	return nil
}

func (p *snellV5Packet) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writeDeadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	if p.child != nil {
		return p.child.SetWriteDeadline(t)
	}
	return nil
}

type snellRawPacket struct {
	net.Conn
	key         *wire.Key
	dst         access.Endpoint
	established bool
}

func (p *snellRawPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	if len(b) == 0 || len(b) > wire.MaxQUICProxyPayload {
		return 0, wire.ErrFrame
	}
	data := b
	if !p.established || wire.QUICInitial(b) {
		var err error
		data, err = wire.ProtectQUIC(p.key, p.dst, b)
		if err != nil {
			return 0, err
		}
	} else if !wire.QUICRaw(b) {
		return 0, wire.ErrFrame
	}
	n, err := p.Conn.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	p.established = true
	return len(b), nil
}

func (p *snellRawPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Conn.Read(b)
	return n, netaddr.UDP(p.dst), err
}
