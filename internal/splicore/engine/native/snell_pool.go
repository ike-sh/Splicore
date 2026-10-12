package native

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
	"net"
	"sync"
	"time"
)

const snellMaxSessions = 64
const snellMaxIdle = 8
const snellIdleTimeout = 30 * time.Second

type snellPool struct {
	mu          sync.Mutex
	dial        func(context.Context) (net.Conn, error)
	key         *wire.Key
	all         map[*snellSession]bool
	idle        []*snellSession
	opening     int
	closed      bool
	idleTimeout time.Duration
	timers      sync.WaitGroup
}
type snellSession struct {
	session    *wire.Session
	raw        net.Conn
	timer      *time.Timer
	generation uint64
	timerDone  func()
}

func newSnellPool(dial func(context.Context) (net.Conn, error), key *wire.Key) *snellPool {
	return &snellPool{dial: dial, key: key, all: map[*snellSession]bool{}, idleTimeout: snellIdleTimeout}
}
func (p *snellPool) acquire(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	p.mu.Lock()
	if ctx.Err() != nil {
		p.mu.Unlock()
		return nil, ctx.Err()
	}
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	for len(p.idle) > 0 {
		s := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if s.timer.Stop() {
			s.timerDone()
		}
		s.timer = nil
		s.generation++
		c, e := s.session.Open(dst)
		if e == nil {
			_ = s.raw.SetDeadline(time.Time{})
			p.mu.Unlock()
			return &snellBorrow{Conn: c, pool: p, entry: s}, nil
		}
		delete(p.all, s)
		_ = s.session.Close()
	}
	if len(p.all)+p.opening >= snellMaxSessions {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	p.opening++
	p.mu.Unlock()
	raw, e := p.dial(ctx)
	p.mu.Lock()
	p.opening--
	if e != nil {
		p.mu.Unlock()
		return nil, e
	}
	if ctx.Err() != nil {
		p.mu.Unlock()
		_ = raw.Close()
		return nil, ctx.Err()
	}
	if p.closed {
		p.mu.Unlock()
		_ = raw.Close()
		return nil, net.ErrClosed
	}
	s := &snellSession{session: wire.NewSession(raw, p.key), raw: raw}
	c, e := s.session.Open(dst)
	if e != nil {
		p.mu.Unlock()
		_ = raw.Close()
		return nil, e
	}
	p.all[s] = true
	p.mu.Unlock()
	return &snellBorrow{Conn: c, pool: p, entry: s}, nil
}
func (p *snellPool) release(s *snellSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !s.session.Idle() || len(p.idle) >= snellMaxIdle {
		delete(p.all, s)
		_ = s.session.Close()
		return
	}
	_ = s.raw.SetDeadline(time.Time{})
	p.idle = append(p.idle, s)
	s.generation++
	generation := s.generation
	p.timers.Add(1)
	var done sync.Once
	complete := func() { done.Do(p.timers.Done) }
	s.timerDone = complete
	s.timer = time.AfterFunc(p.idleTimeout, func() {
		defer complete()
		p.mu.Lock()
		defer p.mu.Unlock()
		if s.generation != generation {
			return
		}
		// A canceled timer may already be waiting on mu; verify this entry
		// still belongs to the idle list before closing its physical socket.
		for i, idle := range p.idle {
			if idle == s {
				p.idle = append(p.idle[:i], p.idle[i+1:]...)
				delete(p.all, s)
				_ = s.session.Close()
				return
			}
		}
	})
}
func (p *snellPool) Close() error {
	p.mu.Lock()
	p.closed = true
	for s := range p.all {
		if s.timer != nil {
			if s.timer.Stop() {
				s.timerDone()
			}
		}
		_ = s.session.Close()
		delete(p.all, s)
	}
	p.idle = nil
	p.mu.Unlock()
	p.timers.Wait()
	return nil
}

type snellBorrow struct {
	net.Conn
	pool  *snellPool
	entry *snellSession
	once  sync.Once
}

func (c *snellBorrow) Close() error {
	c.once.Do(func() { _ = c.Conn.Close(); c.pool.release(c.entry) })
	return nil
}
func (c *snellBorrow) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}
