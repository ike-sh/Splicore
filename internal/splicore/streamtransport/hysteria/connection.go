// Package hysteria owns the specialized QUIC/TLS/HTTP3 admission carrier.
// It has no proxy targets, TCPRequest parser, UDP session IDs or routing logic.
package hysteria

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/apernet/quic-go"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/internal/splicore/quiccongestion"
)

// Connection exposes raw library streams/datagrams after admission. Identity
// is assigned once by the binding validator and is immutable for its lifetime.
type Connection struct {
	QUIC       *quic.Conn
	UDP        bool
	ctx        context.Context
	cancel     context.CancelFunc
	identity   atomic.Pointer[string]
	admitted   atomic.Bool
	datagrams  chan []byte
	discarded  atomic.Uint64
	writer     *packetio.Writer
	mu         sync.Mutex
	closing    bool
	workers    sync.WaitGroup
	closeOnce  sync.Once
	done       chan struct{}
	release    func()
	congestion CongestionState
	controller *quiccongestion.Controller
}

func newConnection(q *quic.Conn, release func()) *Connection {
	ctx, cancel := context.WithCancel(q.Context())
	return &Connection{QUIC: q, ctx: ctx, cancel: cancel, writer: packetio.NewWriter(ctx, q.SendDatagram), done: make(chan struct{}), release: release, datagrams: make(chan []byte, 16)}
}
func (c *Connection) Context() context.Context { return c.ctx }
func (c *Connection) Identity() string {
	if id := c.identity.Load(); id != nil {
		return *id
	}
	return ""
}
func (c *Connection) SendDatagram(ctx context.Context, b []byte) error { return c.writer.Send(ctx, b) }
func (c *Connection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	case b := <-c.datagrams:
		return b, nil
	}
}

// Receive from QUIC from the start of a server connection. Pre-auth datagrams
// are discarded instead of becoming queued proxy requests after admission.
func (c *Connection) startDatagrams() {
	c.Go(func() {
		for {
			b, e := c.QUIC.ReceiveDatagram(c.ctx)
			if e != nil {
				return
			}
			if !c.admitted.Load() || !c.UDP {
				c.discarded.Add(1)
				continue
			}
			select {
			case c.datagrams <- b:
			default:
			}
		}
	})
}
func (c *Connection) OpenStream(ctx context.Context) (*quic.Stream, error) {
	if c.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	return c.QUIC.OpenStreamSync(ctx)
}

// Go orders worker registration against shutdown; Close joins all registered
// workers. A worker must return on Context cancellation and never call Close.
func (c *Connection) Go(f func()) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.ctx.Err() != nil {
		return false
	}
	c.workers.Add(1)
	go func() { defer c.workers.Done(); f() }()
	return true
}

// handle registers an HTTP handler synchronously with the same owner gate.
// Shutdown cancels its QUIC request context and waits for upstream/body cleanup.
func (c *Connection) handle(f func()) bool {
	c.mu.Lock()
	if c.closing || c.ctx.Err() != nil {
		c.mu.Unlock()
		return false
	}
	c.workers.Add(1)
	c.mu.Unlock()
	defer c.workers.Done()
	f()
	return true
}
func (c *Connection) Close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		c.mu.Unlock()
		c.cancel()
		_ = c.QUIC.CloseWithError(0x100, "")
		if c.release != nil {
			c.release()
		}
		c.writer.Wait()
		c.workers.Wait()
		close(c.done)
	})
	<-c.done
}
