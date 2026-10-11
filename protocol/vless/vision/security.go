// Package vision implements the VLESS xtls-rprx-vision flow independently of
// socket creation and TLS implementations. No TLS private memory is accessed.
package vision

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// RecordConn prevents the security implementation from reading ahead across
// ciphertext records. After a direct command the same masked underlay retains
// ownership of all bytes beyond the last consumed security record.
type RecordConn struct {
	net.Conn
	header         [5]byte
	pos, remaining int
}

func LimitRecords(c net.Conn) *RecordConn { return &RecordConn{Conn: c} }
func (c *RecordConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.pos == 0 && c.remaining == 0 {
		if _, e := io.ReadFull(c.Conn, c.header[:]); e != nil {
			return 0, e
		}
		c.remaining = int(binary.BigEndian.Uint16(c.header[3:]))
		if c.remaining > 18432 {
			return 0, errors.New("security record exceeds bound")
		}
	}
	if c.pos < 5 {
		n := copy(p, c.header[c.pos:])
		c.pos += n
		return n, nil
	}
	if c.remaining == 0 {
		c.pos = 0
		return c.Read(p)
	}
	n, e := c.Conn.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	if c.remaining == 0 {
		c.pos = 0
	}
	return n, e
}
func (c *RecordConn) CloseWrite() error { return halfWrite(c.Conn) }
func (c *RecordConn) CloseRead() error  { return halfRead(c.Conn) }

// PlainConn consumes a whole plaintext record into owned storage even when
// VLESS requests a one-byte header. It can safely drain the final plaintext at
// the direct transition, without unsafe reflection into TLS buffers.
type PlainConn struct {
	net.Conn
	mu      sync.Mutex
	pending []byte
	err     error
}

func BufferRecords(c net.Conn) *PlainConn { return &PlainConn{Conn: c} }
func (c *PlainConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 && c.err == nil {
		b := make([]byte, 32768)
		n, e := c.Conn.Read(b)
		c.pending = b[:n]
		c.err = e
		if n == 0 && e == nil {
			c.err = io.ErrNoProgress
		}
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return 0, c.err
}
func (c *PlainConn) drain() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.pending
	c.pending = nil
	return b
}
func (c *PlainConn) CloseWrite() error { return halfWrite(c.Conn) }
func (c *PlainConn) CloseRead() error  { return halfRead(c.Conn) }
func halfWrite(c net.Conn) error {
	if c, ok := c.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return errors.New("half-close unsupported")
}
func halfRead(c net.Conn) error {
	if c, ok := c.(interface{ CloseRead() error }); ok {
		return c.CloseRead()
	}
	return errors.New("half-close unsupported")
}
