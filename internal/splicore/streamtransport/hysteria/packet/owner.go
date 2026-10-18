package packet

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Own gates socket writes against final close. QUIC can still have a queued
// connection-close reply after Transport.Close returns; it must not reach a
// released socket. It intentionally exposes only the portable PacketConn API.
func Own(p net.PacketConn) net.PacketConn { return &owner{PacketConn: p} }

type owner struct {
	net.PacketConn
	closing   atomic.Bool
	writes    sync.RWMutex
	deadlines sync.Mutex
	once      sync.Once
	err       error
}

func (p *owner) WriteTo(b []byte, a net.Addr) (int, error) {
	p.writes.RLock()
	defer p.writes.RUnlock()
	if p.closing.Load() {
		return 0, net.ErrClosed
	}
	return p.PacketConn.WriteTo(b, a)
}
func (p *owner) SetWriteDeadline(t time.Time) error {
	p.deadlines.Lock()
	defer p.deadlines.Unlock()
	if p.closing.Load() {
		return net.ErrClosed
	}
	return p.PacketConn.SetWriteDeadline(t)
}
func (p *owner) SetDeadline(t time.Time) error {
	p.deadlines.Lock()
	defer p.deadlines.Unlock()
	if p.closing.Load() {
		return net.ErrClosed
	}
	return p.PacketConn.SetDeadline(t)
}
func (p *owner) Close() error {
	p.once.Do(func() {
		// PacketConn's deadline contract interrupts blocked writes before joining
		// them. Serialize deadline setters so they cannot clear this interruption.
		p.deadlines.Lock()
		p.closing.Store(true)
		_ = p.PacketConn.SetWriteDeadline(time.Now())
		p.deadlines.Unlock()
		p.writes.Lock()
		p.err = p.PacketConn.Close()
		p.writes.Unlock()
	})
	return p.err
}
