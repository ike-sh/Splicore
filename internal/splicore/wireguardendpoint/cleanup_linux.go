//go:build linux

package wireguardendpoint

import (
	"errors"
	"io"
	"net"
	"sync"
)

func cleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &BackendError{Class: CleanupFailure, Operation: operation, Cause: err}
}

// clientio.Owner joins and closes sockets. Preserve their close errors as well
// as link/control/namespace failures in the backend's idempotent Close result.
type kernelCloser struct {
	io.Closer
	backend *kernelBackend
	once    sync.Once
	err     error
}

func (b *kernelBackend) recordCloser(c io.Closer) *kernelCloser {
	return &kernelCloser{Closer: c, backend: b}
}

func (c *kernelCloser) Close() error {
	c.once.Do(func() {
		c.err = c.Closer.Close()
		if c.err != nil {
			c.backend.cleanupMu.Lock()
			c.backend.socketErrors = errors.Join(c.backend.socketErrors, cleanupError("owned socket close", c.err))
			c.backend.cleanupMu.Unlock()
		}
	})
	return c.err
}

type kernelConn struct {
	net.Conn
	closer *kernelCloser
}

func (c *kernelConn) Close() error { return c.closer.Close() }
func (c *kernelConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Close()
}

func (b *kernelBackend) ownConn(c net.Conn) (net.Conn, error) {
	return b.owner.Conn(&kernelConn{Conn: c, closer: b.recordCloser(c)})
}

type kernelPacket struct {
	net.PacketConn
	closer *kernelCloser
}

func (c *kernelPacket) Close() error { return c.closer.Close() }

func (b *kernelBackend) ownPacket(c net.PacketConn) (net.PacketConn, error) {
	return b.owner.Packet(&kernelPacket{PacketConn: c, closer: b.recordCloser(c)})
}
