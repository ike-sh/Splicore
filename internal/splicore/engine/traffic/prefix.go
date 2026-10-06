package traffic

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// Prefix transfers a snapshot of handshake lookahead to the payload reader.
// Close marks the connection and interrupts the underlying socket; it never
// releases or mutates the reader's backing array. The caller can release its
// original handshake buffer immediately after construction.
func Prefix(c net.Conn, lookahead []byte) net.Conn {
	return &prefixConn{Conn: c, prefix: bytes.NewReader(bytes.Clone(lookahead))}
}

type prefixConn struct {
	net.Conn
	prefix *bytes.Reader
	rmu    sync.Mutex
	closed atomic.Bool
}

func (c *prefixConn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.prefix.Len() > 0 {
		return c.prefix.Read(b)
	}
	return c.Conn.Read(b)
}
func (c *prefixConn) Close() error { c.closed.Store(true); return c.Conn.Close() }
func (c *prefixConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return errors.ErrUnsupported
}
func (c *prefixConn) CloseRead() error {
	if h, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return h.CloseRead()
	}
	return errors.ErrUnsupported
}
