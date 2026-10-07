// Package backend adapts modern VMess wire state to owned Go sockets.
package backend

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/protocol/vmess/wire"
)

// Conn serializes each direction separately. Closing the raw socket precedes
// joining operations, so an interrupted frame cannot keep a shutdown waiting.
type Conn struct {
	net.Conn
	request                   wire.Request
	reader, writer            *wire.Chunk
	server, framed            bool
	rmu, wmu, mu              sync.Mutex
	closed, readEOF, writeEOF bool
	readHeader, writeHeader   bool
	buffer                    []byte
	once, closeOnce           sync.Once
	stopParent                func() bool
	parentDone                chan struct{}
}

func newConn(ctx context.Context, raw net.Conn, r wire.Request, server bool) (*Conn, error) {
	rx, err := wire.NewChunk(r, !server, nil)
	if err != nil {
		return nil, err
	}
	tx, err := wire.NewChunk(r, server, nil)
	if err != nil {
		return nil, err
	}
	c := &Conn{Conn: raw, request: r, reader: rx, writer: tx, server: server, framed: r.Options&wire.ChunkStream != 0, readHeader: server, writeHeader: !server, parentDone: make(chan struct{})}
	c.stopParent = context.AfterFunc(ctx, func() { c.retire(); close(c.parentDone) })
	return c, nil
}

// Client sends the authenticated request eagerly. Peers may defer their
// response until the first payload, so Dial does not wait for a response.
func Client(ctx context.Context, raw net.Conn, key wire.Key, r wire.Request, now time.Time) (*Conn, error) {
	b, err := wire.EncodeRequest(key, r, now, nil)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err = writeFull(raw, b); err != nil {
		_ = raw.Close()
		return nil, err
	}
	c, err := newConn(ctx, raw, r, false)
	if err != nil {
		_ = raw.Close()
	}
	return c, err
}
func Server(ctx context.Context, raw net.Conn, r wire.Request) (*Conn, error) {
	return newConn(ctx, raw, r, true)
}
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (c *Conn) alive() bool { c.mu.Lock(); defer c.mu.Unlock(); return !c.closed }
func (c *Conn) retire() {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		// TLS Close can need the write lock for close_notify. Interrupt the
		// raw socket before joining a write that may already hold that lock.
		if wrapped, ok := c.Conn.(interface{ NetConn() net.Conn }); ok {
			_ = wrapped.NetConn().Close()
		}
		_ = c.Conn.Close()
	})
}
func (c *Conn) response() error {
	if !c.readHeader {
		if err := wire.ReadResponse(c.Conn, c.request); err != nil {
			return err
		}
		c.readHeader = true
	}
	return nil
}
func (c *Conn) prefix() error {
	if !c.writeHeader {
		if err := writeFull(c.Conn, wire.EncodeResponse(c.request)); err != nil {
			return err
		}
		c.writeHeader = true
	}
	return nil
}
func (c *Conn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if !c.alive() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	if c.readEOF {
		return 0, io.EOF
	}
	if err := c.response(); err != nil {
		c.retire()
		return 0, err
	}
	if !c.framed {
		n, err := c.Conn.Read(b)
		if err == io.EOF {
			c.readEOF = true
		} else if err != nil {
			c.retire()
		}
		return n, err
	}
	if len(c.buffer) == 0 {
		v, err := c.reader.Read(c.Conn)
		if err != nil {
			if err == io.EOF {
				c.readEOF = true
			} else {
				c.retire()
			}
			return 0, err
		}
		c.buffer = v
	}
	n := copy(b, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}
func (c *Conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if !c.alive() || c.writeEOF {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	if err := c.prefix(); err != nil {
		c.retire()
		return 0, err
	}
	if !c.framed {
		n, err := c.Conn.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
		if err != nil {
			c.retire()
		}
		return n, err
	}
	total := 0
	for len(b) > 0 {
		n := min(len(b), c.writer.MaxPayload())
		frame, err := c.writer.Encode(b[:n])
		if err == nil {
			err = writeFull(c.Conn, frame)
		}
		if err != nil {
			c.retire()
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

// Datagrams are never split into TCP-sized chunks or coalesced with one another.
func (c *Conn) writePacket(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if !c.alive() || c.writeEOF {
		return net.ErrClosed
	}
	if len(b) == 0 || len(b) > c.writer.MaxPayload() {
		return wire.ErrFrame
	}
	if err := c.prefix(); err != nil {
		c.retire()
		return err
	}
	frame, err := c.writer.Encode(b)
	if err == nil {
		err = writeFull(c.Conn, frame)
	}
	if err != nil {
		c.retire()
	}
	return err
}
func (c *Conn) readPacket() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if !c.alive() {
		return nil, net.ErrClosed
	}
	if err := c.response(); err != nil {
		c.retire()
		return nil, err
	}
	b, err := c.reader.Read(c.Conn)
	if err != nil {
		c.retire()
	}
	return b, err
}
func (c *Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if !c.alive() {
		return net.ErrClosed
	}
	if c.writeEOF {
		return nil
	}
	if err := c.prefix(); err != nil {
		c.retire()
		return err
	}
	c.writeEOF = true
	if c.framed {
		frame, err := c.writer.Encode(nil)
		if err == nil {
			err = writeFull(c.Conn, frame)
		}
		if err != nil {
			c.retire()
		}
		return err
	}
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	// A wrapper without half-close cannot signal an unframed upload EOF safely.
	c.retire()
	return nil
}
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.retire()
		if !c.stopParent() {
			<-c.parentDone
		}
		c.wmu.Lock()
		c.wmu.Unlock()
		c.rmu.Lock()
		clear(c.buffer)
		c.buffer = nil
		c.rmu.Unlock()
	})
	return nil
}
