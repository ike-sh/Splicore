package packet

import (
	"net"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

// Hopping keeps one resolved IP, one protected socket and one logical peer.
// Only the physical destination port changes. Eligible late replies are
// normalized before QUIC sees them; neither DNS nor QUIC is restarted.
type Hopping struct {
	net.PacketConn
	peer         net.UDPAddr
	ports        cfg.PortSet
	policy       cfg.HysteriaUDP
	mu           sync.Mutex
	current      uint16
	closed       bool
	done, exited chan struct{}
	once         sync.Once
	closeErr     error
}

func Hop(p net.PacketConn, address net.Addr, u *cfg.HysteriaUDP) (net.PacketConn, net.Addr, error) {
	if u == nil || u.Ports == "" {
		return p, address, nil
	}
	peer, ok := address.(*net.UDPAddr)
	if p == nil || !ok || peer == nil || peer.IP == nil || u.Validate() != nil || u.ServerPortRange != "" {
		return nil, nil, ErrPacket
	}
	ports, e := cfg.ParseHysteriaPorts(u.Ports)
	if e != nil {
		return nil, nil, ErrPacket
	}
	initial, e := ports.Select(0)
	if e != nil {
		return nil, nil, e
	}
	c := &Hopping{PacketConn: p, peer: *peer, ports: ports, policy: *u, current: initial, done: make(chan struct{}), exited: make(chan struct{})}
	c.peer.IP = append(net.IP(nil), peer.IP...)
	if ports.Len() > 1 {
		go c.schedule()
	} else {
		close(c.exited)
	}
	return c, c.logical(), nil
}
func (c *Hopping) logical() *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), c.peer.IP...), Port: c.peer.Port, Zone: c.peer.Zone}
}
func (c *Hopping) schedule() {
	defer close(c.exited)
	for {
		interval, e := c.policy.Interval()
		if e != nil {
			return
		}
		timer := time.NewTimer(interval)
		select {
		case <-c.done:
			timer.Stop()
			return
		case <-timer.C:
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		next, e := c.ports.Select(c.current)
		if e == nil {
			c.current = next
		}
		c.mu.Unlock()
		// Entropy failure fails closed instead of silently retaining a hop policy.
		if e != nil {
			_ = c.PacketConn.Close()
			return
		}
	}
}
func (c *Hopping) WriteTo(p []byte, to net.Addr) (int, error) {
	a, ok := to.(*net.UDPAddr)
	if !ok || a == nil || !a.IP.Equal(c.peer.IP) || a.Zone != c.peer.Zone || a.Port != c.peer.Port {
		return 0, ErrPacket
	}
	c.mu.Lock()
	closed, port := c.closed, c.current
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	physical := c.logical()
	physical.Port = int(port)
	return c.PacketConn.WriteTo(p, physical)
}
func (c *Hopping) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, e := c.PacketConn.ReadFrom(p)
		if e != nil {
			return 0, nil, e
		}
		a, ok := from.(*net.UDPAddr)
		if !ok || a == nil || !a.IP.Equal(c.peer.IP) || a.Zone != c.peer.Zone || a.Port < 1 || a.Port > 65535 || !c.ports.Contains(uint16(a.Port)) {
			continue
		}
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return 0, nil, net.ErrClosed
		}
		return n, c.logical(), nil
	}
}
func (c *Hopping) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.done)
		c.closeErr = c.PacketConn.Close()
		<-c.exited
	})
	return c.closeErr
}
