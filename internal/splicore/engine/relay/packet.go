package relay

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
)

// Packets owns each numeric target socket and joins every reply/idle worker
// before returning its borrowed protocol packet. Each reader has private scratch.
func Packets(ctx context.Context, packet net.PacketConn, dial func(context.Context, access.Endpoint) (net.Conn, error), idle time.Duration) error {
	p := newPacketRelay(packet, dial, idle)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { p.shutdown(); close(interrupted) })
	defer func() {
		p.shutdown()
		if !stop() {
			<-interrupted
		}
	}()
	buffer := make([]byte, 65535)
	for {
		if idle > 0 {
			_ = packet.SetReadDeadline(time.Now().Add(idle))
		}
		n, a, err := packet.ReadFrom(buffer)
		if err != nil {
			return err
		}
		dst, err := netaddr.From(a)
		if err != nil {
			return err
		}
		if err = p.write(ctx, dst, buffer[:n]); err != nil {
			return err
		}
	}
}

type packetRelay struct {
	mu      sync.Mutex
	targets map[access.Endpoint]*packetTarget
	closing bool
	workers sync.WaitGroup
	packet  net.PacketConn
	dial    func(context.Context, access.Endpoint) (net.Conn, error)
	idle    time.Duration
}

// Membership, terminal and last are guarded by the parent's mu. No blocking
// operation is performed while holding that mutex.
type packetTarget struct {
	key                        access.Endpoint
	conn                       net.Conn
	last                       time.Time
	terminal                   bool
	stop, readerDone, idleDone chan struct{}
	closeOnce                  sync.Once
}

func newPacketRelay(packet net.PacketConn, dial func(context.Context, access.Endpoint) (net.Conn, error), idle time.Duration) *packetRelay {
	return &packetRelay{targets: make(map[access.Endpoint]*packetTarget), packet: packet, dial: dial, idle: idle}
}

func (p *packetRelay) target(ctx context.Context, dst access.Endpoint) (*packetTarget, error) {
	p.mu.Lock()
	if p.closing || ctx.Err() != nil {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	if t := p.targets[dst]; t != nil {
		p.mu.Unlock()
		return t, nil
	}
	full := len(p.targets) >= 128
	p.mu.Unlock()
	if full {
		return nil, net.InvalidAddrError("too many UDP targets")
	}
	c, err := p.dial(ctx, dst)
	if err != nil {
		return nil, err
	}
	t := &packetTarget{key: dst, conn: c, last: time.Now(), stop: make(chan struct{}), readerDone: make(chan struct{}), idleDone: make(chan struct{})}
	p.mu.Lock()
	if p.closing || ctx.Err() != nil {
		p.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	if existing := p.targets[dst]; existing != nil {
		p.mu.Unlock()
		_ = c.Close()
		return existing, nil
	}
	if len(p.targets) >= 128 {
		p.mu.Unlock()
		_ = c.Close()
		return nil, net.InvalidAddrError("too many UDP targets")
	}
	p.targets[dst] = t
	p.workers.Add(1)
	if p.idle > 0 {
		p.workers.Add(1)
	}
	p.mu.Unlock()
	go p.read(t)
	if p.idle > 0 {
		go p.watchIdle(t)
	} else {
		close(t.idleDone)
	}
	return t, nil
}

func (p *packetRelay) touch(t *packetTarget, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || t.terminal || p.targets[t.key] != t {
		return false
	}
	if now.After(t.last) {
		t.last = now
	}
	return true
}

func (p *packetRelay) write(ctx context.Context, dst access.Endpoint, b []byte) error {
	// At most one retry if retirement wins before admission. Socket errors retire
	// only that target; the next datagram dials anew without disturbing siblings.
	// Never retry a write that may already have reached the network.
	for range 2 {
		t, err := p.target(ctx, dst)
		if err != nil {
			return err
		}
		if !p.touch(t, time.Now()) {
			continue
		}
		n, err := t.conn.Write(b)
		if err != nil || n != len(b) {
			p.retire(t)
			return nil
		}
		p.touch(t, time.Now())
		return nil
	}
	return nil
}

// detachLocked is the sole terminal transition. A delayed old reader/timer
// must never delete a replacement registered under the same key.
func (p *packetRelay) detachLocked(t *packetTarget) {
	if !t.terminal {
		t.terminal = true
		close(t.stop)
	}
	if p.targets[t.key] == t {
		delete(p.targets, t.key)
	}
}
func (t *packetTarget) closeSocket() { t.closeOnce.Do(func() { _ = t.conn.Close() }) }
func (p *packetRelay) retire(t *packetTarget) {
	p.mu.Lock()
	p.detachLocked(t)
	p.mu.Unlock()
	t.closeSocket()
}

func (p *packetRelay) read(t *packetTarget) {
	defer p.workers.Done()
	defer close(t.readerDone)
	defer p.retire(t)
	scratch := make([]byte, 65535)
	for {
		n, err := t.conn.Read(scratch)
		// Preserve terminal-on-read-error policy. The net poller handles EINTR/EAGAIN;
		// there is no target read deadline or unbounded Temporary retry loop here.
		if err != nil {
			return
		}
		if !p.touch(t, time.Now()) {
			return
		}
		if p.idle > 0 {
			_ = p.packet.SetReadDeadline(time.Now().Add(p.idle))
		}
		if _, err = p.packet.WriteTo(scratch[:n], t.conn.RemoteAddr()); err != nil {
			// A framed parent write failure may consume a prefix. Preserve the adapter's
			// terminal stream semantics and unblock ReadFrom.
			_ = p.packet.Close()
			return
		}
	}
}

// expire checks activity and transitions atomically with write admission.
func (p *packetRelay) expire(t *packetTarget, now time.Time) (bool, time.Duration) {
	p.mu.Lock()
	if t.terminal || p.closing || p.targets[t.key] != t {
		p.mu.Unlock()
		return true, 0
	}
	remaining := t.last.Add(p.idle).Sub(now)
	if remaining > 0 {
		p.mu.Unlock()
		return false, remaining
	}
	p.detachLocked(t)
	p.mu.Unlock()
	t.closeSocket()
	return true, 0
}
func (p *packetRelay) watchIdle(t *packetTarget) {
	defer p.workers.Done()
	defer close(t.idleDone)
	timer := time.NewTimer(p.idle)
	defer timer.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-timer.C:
			done, remaining := p.expire(t, time.Now())
			if done {
				return
			}
			timer.Reset(remaining)
		}
	}
}
func (p *packetRelay) shutdown() {
	p.mu.Lock()
	p.closing = true
	all := make([]*packetTarget, 0, len(p.targets))
	for _, t := range p.targets {
		all = append(all, t)
		p.detachLocked(t)
	}
	p.mu.Unlock()
	_ = p.packet.Close()
	for _, t := range all {
		t.closeSocket()
	}
	p.workers.Wait()
}
