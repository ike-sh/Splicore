// Package clientio owns adapter sockets and pending dials without locking payload I/O.
package clientio

import (
	"context"
	"io"
	"net"
	"sync"
)

type Owner struct {
	mu      sync.Mutex
	sockets map[io.Closer]bool
	closed  bool
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
}

func New() *Owner {
	ctx, cancel := context.WithCancel(context.Background())
	return &Owner{sockets: map[io.Closer]bool{}, ctx: ctx, cancel: cancel}
}

// Begin orders Add before Close's Wait and ties dials to adapter shutdown.
func (o *Owner) Begin(ctx context.Context) (context.Context, func(), error) {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	o.wg.Add(1)
	o.mu.Unlock()
	joined, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(o.ctx, cancel)
	return joined, func() { stop(); cancel(); o.wg.Done() }, nil
}
func (o *Owner) add(c io.Closer) error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		_ = c.Close()
		return net.ErrClosed
	}
	o.sockets[c] = true
	o.mu.Unlock()
	return nil
}
func (o *Owner) remove(c io.Closer) { o.mu.Lock(); delete(o.sockets, c); o.mu.Unlock() }
func (o *Owner) Conn(c net.Conn) (net.Conn, error) {
	w := &conn{Conn: c, owner: o}
	if err := o.add(w); err != nil {
		return nil, err
	}
	return w, nil
}
func (o *Owner) Packet(c net.PacketConn) (net.PacketConn, error) {
	w := &packet{PacketConn: c, owner: o}
	if err := o.add(w); err != nil {
		return nil, err
	}
	return w, nil
}
func (o *Owner) Close() {
	o.once.Do(func() {
		o.mu.Lock()
		o.closed = true
		o.cancel()
		all := make([]io.Closer, 0, len(o.sockets))
		for c := range o.sockets {
			all = append(all, c)
		}
		o.mu.Unlock()
		for _, c := range all {
			_ = c.Close()
		}
		o.wg.Wait()
	})
}

type conn struct {
	net.Conn
	owner *Owner
	once  sync.Once
	err   error
}

func (c *conn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.owner.remove(c) })
	return c.err
}
func (c *conn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Close()
}

type packet struct {
	net.PacketConn
	owner *Owner
	once  sync.Once
	err   error
}

func (c *packet) Close() error {
	c.once.Do(func() { c.err = c.PacketConn.Close(); c.owner.remove(c) })
	return c.err
}
