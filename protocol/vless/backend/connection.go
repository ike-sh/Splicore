// Package backend adapts owned VLESS streams and packet sessions. Socket
// creation and authentication policy are supplied explicitly by native runtime.
package backend

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/protocol/vless/wire"
	"io"
	"net"
	"sync"
)

// Conn serializes the initial server response with payload writes. The client
// consumes the response once on Read, so request payload can precede a reply.
type Conn struct {
	net.Conn
	Server                  bool
	rmu, wmu                sync.Mutex
	readHeader, writeHeader bool
	readErr                 error
	writeErr                error
}

func (c *Conn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if !c.Server && !c.readHeader {
		c.readHeader = true
		c.readErr = wire.ReadResponse(c.Conn)
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(b)
}
func (c *Conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.Server && !c.writeHeader {
		n, err := c.Conn.Write([]byte{0, 0})
		if err == nil && n != 2 {
			err = io.ErrShortWrite
		}
		if err != nil {
			// A failed response header cannot be replayed on this stream.
			c.writeErr = net.ErrClosed
			_ = c.Conn.Close()
			return 0, err
		}
		c.writeHeader = true
	}
	return c.Conn.Write(b)
}
func (c *Conn) CloseWrite() error {
	if c, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return c.Conn.Close()
}
func (c *Conn) CloseRead() error {
	if c, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return c.CloseRead()
	}
	return nil
}
func Client(ctx context.Context, c net.Conn, uuid [16]byte, dst access.Endpoint, packet bool) (net.Conn, error) {
	command := wire.TCP
	if packet {
		command = wire.Mux
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if err := wire.WriteRequest(c, wire.Request{UUID: uuid, Command: command, Destination: dst}); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &Conn{Conn: c}, nil
}
