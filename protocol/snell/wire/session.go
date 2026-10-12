package wire

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Session preserves record directions across serial logical TCP requests.
// A borrower must Close before Open may succeed again. Only a joined, clean
// bidirectional logical EOF releases the transport for another use.
type Session struct {
	mu           sync.Mutex
	t            *transport
	busy, closed bool
}

func NewSession(c net.Conn, k *Key) *Session { return &Session{t: newTransport(c, k)} }
func (s *Session) Open(dst access.Endpoint) (net.Conn, error) {
	q := Request{Command: 5, Destination: dst}
	if _, e := EncodeRequest(q); e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.busy {
		return nil, net.ErrClosed
	}
	s.busy = true
	t := &Tunnel{Conn: s.t.raw, t: s.t, request: q, reusable: true}
	return &sessionBorrow{Tunnel: t, session: s}, nil
}
func (s *Session) Close() error { s.mu.Lock(); s.closed = true; s.mu.Unlock(); return s.t.raw.Close() }
func (s *Session) Idle() bool   { s.mu.Lock(); defer s.mu.Unlock(); return !s.busy && !s.closed }

type sessionBorrow struct {
	*Tunnel
	session *Session
	once    sync.Once
	closed  atomic.Bool
}

func (c *sessionBorrow) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		// Join both directions before handing record state back. Incomplete I/O
		// is interrupted by closing the physical connection.
		if !c.readEnd.Load() || !c.writeEnd.Load() {
			_ = c.session.Close()
		}
		c.rmu.Lock()
		c.wmu.Lock()
		c.session.mu.Lock()
		c.session.busy = false
		c.session.mu.Unlock()
		c.wmu.Unlock()
		c.rmu.Unlock()
	})
	return nil
}

func (c *sessionBorrow) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.Tunnel.Read(p)
}
func (c *sessionBorrow) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.Tunnel.Write(p)
}
func (c *sessionBorrow) CloseWrite() error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Tunnel.CloseWrite()
}
func (c *sessionBorrow) deadline(t time.Time, which int) error {
	c.session.mu.Lock()
	defer c.session.mu.Unlock()
	if c.closed.Load() || c.session.closed {
		return net.ErrClosed
	}
	switch which {
	case 1:
		return c.Conn.SetReadDeadline(t)
	case 2:
		return c.Conn.SetWriteDeadline(t)
	default:
		return c.Conn.SetDeadline(t)
	}
}
func (c *sessionBorrow) SetDeadline(t time.Time) error      { return c.deadline(t, 0) }
func (c *sessionBorrow) SetReadDeadline(t time.Time) error  { return c.deadline(t, 1) }
func (c *sessionBorrow) SetWriteDeadline(t time.Time) error { return c.deadline(t, 2) }

// ClientTCPNoReuse emits the non-reusable command for explicit v4 policy.
func ClientTCPNoReuse(c net.Conn, k *Key, dst access.Endpoint) (net.Conn, error) {
	q := Request{Command: 1, Destination: dst}
	if _, e := EncodeRequest(q); e != nil {
		return nil, e
	}
	return &Tunnel{Conn: c, t: newTransport(c, k), request: q}, nil
}
