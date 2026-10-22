//go:build with_quic

package session

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	quic "github.com/metacubex/jls-quic-go"
)

type datagram struct {
	data []byte
	dst  access.Endpoint
	at   time.Time
	id   uint16
}
type destination struct {
	packet   *packet
	endpoint access.Endpoint
}
type connection struct {
	mu        sync.Mutex
	conn      *quic.Conn
	limits    Limits
	closing   bool
	packets   map[*packet]bool
	receive   map[uint16]destination
	pending   []datagram
	next      uint32
	sent      int
	allocated map[*packet]int
	seen      [1024]uint64
	streams   chan struct{}
	wg        sync.WaitGroup
	once      sync.Once
}

func newConnection(q *quic.Conn, l Limits) *connection {
	l = l.Defaults()
	c := &connection{conn: q, limits: l, packets: map[*packet]bool{}, receive: map[uint16]destination{}, allocated: map[*packet]int{}, streams: make(chan struct{}, l.MaxStreams)}
	c.wg.Add(1)
	go c.datagrams()
	return c
}

func (c *connection) open(ctx context.Context) (*stream, error) {
	select {
	case c.streams <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.conn.Context().Done():
		return nil, net.ErrClosed
	}
	st, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		<-c.streams
		return nil, err
	}
	return &stream{Stream: st, conn: c.conn, afterClose: func() { <-c.streams }}, nil
}

func (c *connection) packet(ctrl *stream, pinned *access.Endpoint) (*packet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.conn.Context().Err() != nil {
		return nil, net.ErrClosed
	}
	if len(c.packets) >= c.limits.MaxFlows {
		return nil, ErrLimit
	}
	p := &packet{conn: c, ctrl: ctrl, pinned: pinned, closed: make(chan struct{}), received: make(chan datagram, 32), changed: make(chan struct{}), gate: make(chan struct{}, 1), send: map[access.Endpoint]uint16{}, last: time.Now()}
	c.packets[p] = true
	c.wg.Add(2)
	go p.control()
	go p.watchIdle()
	return p, nil
}

func (c *connection) deliver(p *packet, d datagram) {
	select {
	case <-p.closed:
		return
	default:
	}
	select {
	case p.received <- d:
		p.touch()
	default:
	} // UDP loss under bounded backpressure.
}

func (c *connection) datagrams() {
	defer c.wg.Done()
	defer c.abortPackets()
	for {
		b, err := c.conn.ReceiveDatagram(c.conn.Context())
		if err != nil {
			return
		}
		if len(b) < 2 || len(b) > MaxPayload+2 {
			continue
		}
		id := binary.BigEndian.Uint16(b)
		d := datagram{data: append([]byte(nil), b[2:]...), id: id, at: time.Now()}
		c.mu.Lock()
		if target, ok := c.receive[id]; ok {
			d.dst = target.endpoint
			c.deliver(target.packet, d)
		} else if c.seen[id/64]&(uint64(1)<<(id%64)) == 0 {
			c.expirePending(d.at)
			if len(c.pending) < 32 {
				c.pending = append(c.pending, d)
			}
		}
		c.mu.Unlock()
	}
}

func (c *connection) expirePending(now time.Time) {
	out := c.pending[:0]
	for _, d := range c.pending {
		if now.Sub(d.at) < time.Second {
			out = append(out, d)
		}
	}
	clear(c.pending[len(out):])
	c.pending = out
}

func (c *connection) register(p *packet, dst access.Endpoint, id uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || !c.packets[p] {
		return net.ErrClosed
	}
	if old, ok := c.receive[id]; ok {
		if old.packet != p || old.endpoint != dst {
			return ErrProtocol
		}
		return nil
	}
	if c.seen[id/64]&(uint64(1)<<(id%64)) != 0 {
		return ErrProtocol
	}
	if p.pinned != nil && !sameUDPEndpoint(*p.pinned, dst) || len(c.receive) >= c.limits.MaxFlows {
		return ErrLimit
	}
	c.receive[id] = destination{p, dst}
	c.seen[id/64] |= uint64(1) << (id % 64)
	c.expirePending(time.Now())
	out := c.pending[:0]
	for _, d := range c.pending {
		if d.id == id {
			d.dst = dst
			c.deliver(p, d)
		} else {
			out = append(out, d)
		}
	}
	clear(c.pending[len(out):])
	c.pending = out
	return nil
}

func (c *connection) allocate(p *packet) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || !c.packets[p] {
		return 0, net.ErrClosed
	}
	if c.next > 65535 || c.sent >= c.limits.MaxFlows {
		return 0, ErrLimit
	}
	id := uint16(c.next)
	c.next++
	c.sent++
	c.allocated[p]++
	return id, nil
}

func (c *connection) remove(p *packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.packets, p)
	c.sent -= c.allocated[p]
	delete(c.allocated, p)
	for id, target := range c.receive {
		if target.packet == p {
			delete(c.receive, id)
		}
	}
}

func (c *connection) abortPackets() {
	c.mu.Lock()
	all := make([]*packet, 0, len(c.packets))
	for p := range c.packets {
		all = append(all, p)
	}
	c.mu.Unlock()
	for _, p := range all {
		_ = p.Close()
	}
}

func (c *connection) close() {
	c.once.Do(func() {
		c.mu.Lock()
		c.closing = true
		clear(c.pending)
		c.pending = nil
		c.mu.Unlock()
		_ = c.conn.CloseWithError(0, "")
		c.abortPackets()
		c.wg.Wait()
	})
}

type packet struct {
	mu                          sync.Mutex
	conn                        *connection
	ctrl                        *stream
	pinned                      *access.Endpoint
	closed                      chan struct{}
	received                    chan datagram
	once                        sync.Once
	changed                     chan struct{}
	readDeadline, writeDeadline time.Time
	gate                        chan struct{}
	last                        time.Time
	send                        map[access.Endpoint]uint16 // protected by gate, never by the deadline mutex.
}

func (p *packet) touch() { p.mu.Lock(); p.last = time.Now(); p.mu.Unlock() }
func (p *packet) watchIdle() {
	defer p.conn.wg.Done()
	timer := time.NewTimer(p.conn.limits.UDPIdle())
	defer timer.Stop()
	for {
		select {
		case <-p.closed:
			return
		case <-timer.C:
			p.mu.Lock()
			remaining := time.Until(p.last.Add(p.conn.limits.UDPIdle()))
			p.mu.Unlock()
			if remaining <= 0 {
				_ = p.Close()
				return
			}
			timer.Reset(remaining)
		}
	}
}

func (p *packet) control() {
	defer p.conn.wg.Done()
	defer p.Close()
	for {
		dst, id, err := readMapping(p.ctrl)
		if err != nil || p.conn.register(p, dst, id) != nil {
			return
		}
	}
}

func (p *packet) deadline(write bool) (time.Time, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if write {
		return p.writeDeadline, p.changed
	}
	return p.readDeadline, p.changed
}

func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(time.Until(deadline))
	return timer, timer.C
}

func (p *packet) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case <-p.closed:
			return 0, nil, net.ErrClosed
		default:
		}
		deadline, changed := p.deadline(false)
		if !deadline.IsZero() && !deadline.After(time.Now()) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timer, expired := deadlineTimer(deadline)
		select {
		case d := <-p.received:
			if timer != nil {
				timer.Stop()
			}
			n := copy(b, d.data)
			if n != len(d.data) {
				return n, netaddr.UDP(d.dst), io.ErrShortBuffer
			}
			return n, netaddr.UDP(d.dst), nil
		case <-p.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-expired:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

func (p *packet) writeGate() error {
	for {
		deadline, changed := p.deadline(true)
		if !deadline.IsZero() && !deadline.After(time.Now()) {
			return os.ErrDeadlineExceeded
		}
		timer, expired := deadlineTimer(deadline)
		select {
		case p.gate <- struct{}{}:
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-p.closed:
			if timer != nil {
				timer.Stop()
			}
			return net.ErrClosed
		case <-expired:
			return os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

// sameUDPEndpoint compares IPs and ports without resolving semantic hostnames.
// Hostnames retain their exact identity; invalid endpoints (including zones) fail closed.
func sameUDPEndpoint(a, b access.Endpoint) bool {
	if a.Validate() != nil || b.Validate() != nil {
		return false
	}
	ipA, errA := netip.ParseAddr(a.Host)
	ipB, errB := netip.ParseAddr(b.Host)
	if errA == nil && errB == nil {
		return netip.AddrPortFrom(ipA.Unmap(), a.Port) == netip.AddrPortFrom(ipB.Unmap(), b.Port)
	}
	return errA != nil && errB != nil && a == b
}

func (p *packet) WriteTo(b []byte, a net.Addr) (int, error) {
	if len(b) > MaxPayload {
		return 0, ErrLimit
	}
	dst, err := netaddr.From(a)
	if err != nil || dst.Validate() != nil || p.pinned != nil && !sameUDPEndpoint(*p.pinned, dst) {
		return 0, ErrProtocol
	}
	if err = p.writeGate(); err != nil {
		return 0, err
	}
	defer func() { <-p.gate }()
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	id, ok := p.send[dst]
	if !ok {
		if len(p.send) >= p.conn.limits.MaxFlows {
			return 0, ErrLimit
		}
		id, err = p.conn.allocate(p)
		if err != nil {
			return 0, err
		}
		header, err := mapping(dst, id)
		if err != nil {
			return 0, err
		}
		if _, err = p.ctrl.Write(header); err != nil {
			_ = p.Close()
			return 0, err
		}
		p.send[dst] = id
	}
	frame := make([]byte, 2, len(b)+2)
	binary.BigEndian.PutUint16(frame, id)
	if err = p.conn.conn.SendDatagram(append(frame, b...)); err != nil {
		return 0, err
	}
	p.touch()
	return len(b), nil
}

func (p *packet) Close() error {
	p.once.Do(func() { close(p.closed); _ = p.ctrl.Close(); p.conn.remove(p) })
	return nil
}
func (p *packet) LocalAddr() net.Addr { return p.conn.conn.LocalAddr() }
func (p *packet) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline, p.writeDeadline = t, t
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	return p.ctrl.SetWriteDeadline(t)
}

func (p *packet) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	return nil
}

func (p *packet) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeDeadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	return p.ctrl.SetWriteDeadline(t)
}
