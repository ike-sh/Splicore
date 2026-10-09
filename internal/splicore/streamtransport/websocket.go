package streamtransport

import (
	"context"
	"errors"
	"github.com/gorilla/websocket"
	"io"
	"net"
	"sync"
	"time"
)

// Gorilla writes its stored deadline on frame flush. This socket applies the
// latest user deadline instead, so SetWriteDeadline also affects blocked I/O.
type wsSocket struct {
	net.Conn
	mu    sync.Mutex
	at    time.Time
	limit *headerReader
}

func (c *wsSocket) update(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = t
	return c.Conn.SetWriteDeadline(t)
}
func (c *wsSocket) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && (t.IsZero() || c.at.Before(t)) {
		t = c.at
	}
	return c.Conn.SetWriteDeadline(t)
}

type wsConn struct {
	ws     *websocket.Conn
	socket *wsSocket
	read   io.Reader
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	rg, wg chan struct{}
	rd, wd deadline
}

func newWS(ws *websocket.Conn) *wsConn {
	if socket, ok := ws.UnderlyingConn().(*wsSocket); ok && socket.limit != nil {
		socket.limit.n = -1
	}
	ws.SetReadLimit(MaxMessage)
	ctx, cancel := context.WithCancel(context.Background())
	c := &wsConn{ws: ws, socket: ws.UnderlyingConn().(*wsSocket), ctx: ctx, cancel: cancel, rg: make(chan struct{}, 1), wg: make(chan struct{}, 1)}
	c.rg <- struct{}{}
	c.wg <- struct{}{}
	return c
}
func (c *wsConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if e := acquire(c.ctx, c.rg, &c.rd); e != nil {
		return 0, e
	}
	defer func() { c.rg <- struct{}{} }()
	for {
		if c.read == nil {
			kind, r, e := c.ws.NextReader()
			if e != nil {
				c.Close()
				if websocket.IsCloseError(e, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					e = io.EOF
				}
				return 0, e
			}
			if kind != websocket.BinaryMessage {
				c.Close()
				return 0, errors.New("non-binary WebSocket transport message")
			}
			c.read = r
		}
		n, e := c.read.Read(p)
		if e == io.EOF {
			c.read = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		if e != nil {
			c.Close()
		}
		return n, e
	}
}
func (c *wsConn) Write(p []byte) (int, error) {
	if e := acquire(c.ctx, c.wg, &c.wd); e != nil {
		return 0, e
	}
	defer func() { c.wg <- struct{}{} }()
	total := 0
	for len(p) > 0 {
		n := min(len(p), ChunkSize)
		if e := c.ws.WriteMessage(websocket.BinaryMessage, p[:n]); e != nil {
			c.Close()
			return total, e
		}
		total += n
		p = p[n:]
		if c.ctx.Err() != nil {
			return total, net.ErrClosed
		}
	}
	return total, nil
}
func (c *wsConn) Close() error {
	var e error
	c.once.Do(func() { c.cancel(); e = c.ws.Close() })
	return e
}
func (c *wsConn) LocalAddr() net.Addr                { return c.socket.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.socket.RemoteAddr() }
func (c *wsConn) SetReadDeadline(t time.Time) error  { c.rd.set(t); return c.socket.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { c.wd.set(t); return c.socket.update(t) }
func (c *wsConn) SetDeadline(t time.Time) error {
	e := c.SetReadDeadline(t)
	e2 := c.SetWriteDeadline(t)
	if e != nil {
		return e
	}
	return e2
}

func (c *wsSocket) Read(p []byte) (int, error) {
	if c.limit != nil {
		return c.limit.Read(p)
	}
	return c.Conn.Read(p)
}
func (c *wsSocket) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return errors.New("half-close unsupported")
}
