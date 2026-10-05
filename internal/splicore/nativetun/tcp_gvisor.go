//go:build with_gvisor

package nativetun

import (
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// lazyTCP lets the existing Manager perform routing/policy/outbound admission
// before accepting the local SYN. It owns exactly one forwarder request.
type lazyTCP struct {
	backend                 *gvisorBackend
	request                 *tcp.ForwarderRequest
	id                      stack.TransportEndpointID
	mu                      sync.Mutex
	started, closed         bool
	conn                    *gonet.TCPConn
	err                     error
	ready, initialized      chan struct{}
	readyOnce, completeOnce sync.Once
}

func newLazyTCP(b *gvisorBackend, r *tcp.ForwarderRequest, id stack.TransportEndpointID) *lazyTCP {
	return &lazyTCP{backend: b, request: r, id: id, ready: make(chan struct{}), initialized: make(chan struct{})}
}

func (c *lazyTCP) signalReady()        { c.readyOnce.Do(func() { close(c.ready) }) }
func (c *lazyTCP) complete(reset bool) { c.completeOnce.Do(func() { c.request.Complete(reset) }) }

func (c *lazyTCP) connection() (*gonet.TCPConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if c.started {
		c.mu.Unlock()
		<-c.initialized
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			return nil, net.ErrClosed
		}
		return c.conn, c.err
	}
	c.started = true
	c.mu.Unlock()
	var queue waiter.Queue
	ep, stackErr := c.request.CreateEndpoint(&queue)
	c.signalReady() // also handles early errors before any SYN-ACK output
	c.complete(stackErr != nil)
	c.mu.Lock()
	if stackErr != nil {
		c.err = translate(stackErr)
	} else {
		c.conn = gonet.NewTCPConn(&queue, ep)
		if c.closed {
			_ = c.conn.Close()
			c.err = net.ErrClosed
		}
	}
	close(c.initialized)
	conn, err := c.conn, c.err
	c.mu.Unlock()
	return conn, err
}

func (c *lazyTCP) Close() error {
	c.mu.Lock()
	c.closed = true
	started := c.started
	conn := c.conn
	if !started {
		c.complete(true)
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	// Established flows use normal socket Close so queued data and FIN can
	// finish. Abort is solely the cancellation barrier for endpoint creation.
	if conn != nil {
		return cleanError(conn.Close())
	}
	// The link callback occurs after registration. No unbounded handshake wait
	// and no endpoint can be published after this exact-tuple Abort barrier.
	<-c.ready
	protocol := header.IPv4ProtocolNumber
	if c.id.LocalAddress.BitLen() == 128 {
		protocol = header.IPv6ProtocolNumber
	}
	if ep := c.backend.stack.FindTransportEndpoint(protocol, tcp.ProtocolNumber, c.id, 1); ep != nil {
		ep.Abort()
	}
	<-c.initialized
	c.mu.Lock()
	conn = c.conn
	c.mu.Unlock()
	if conn != nil {
		return cleanError(conn.Close())
	}
	return nil
}

func (c *lazyTCP) Read(p []byte) (int, error) {
	conn, err := c.connection()
	if err != nil {
		return 0, err
	}
	n, err := conn.Read(p)
	return n, cleanError(err)
}
func (c *lazyTCP) Write(p []byte) (int, error) {
	conn, err := c.connection()
	if err != nil {
		return 0, err
	}
	n, err := conn.Write(p)
	return n, cleanError(err)
}
func (c *lazyTCP) CloseWrite() error {
	conn, err := c.connection()
	if err != nil {
		return err
	}
	return cleanError(conn.CloseWrite())
}
func (c *lazyTCP) LocalAddr() net.Addr {
	_, destination := addresses(c.id)
	return net.TCPAddrFromAddrPort(destination)
}
func (c *lazyTCP) RemoteAddr() net.Addr {
	source, _ := addresses(c.id)
	return net.TCPAddrFromAddrPort(source)
}
func (c *lazyTCP) SetDeadline(t time.Time) error {
	conn, err := c.connection()
	if err != nil {
		return err
	}
	return cleanError(conn.SetDeadline(t))
}
func (c *lazyTCP) SetReadDeadline(t time.Time) error {
	conn, err := c.connection()
	if err != nil {
		return err
	}
	return cleanError(conn.SetReadDeadline(t))
}
func (c *lazyTCP) SetWriteDeadline(t time.Time) error {
	conn, err := c.connection()
	if err != nil {
		return err
	}
	return cleanError(conn.SetWriteDeadline(t))
}
