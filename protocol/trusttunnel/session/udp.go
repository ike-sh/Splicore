package session

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
)

// A single reader, serialized bounded writes and a single expiry worker own
// each mux. One socket/receiver per bounded association; none per datagram.
type flowKey struct{ src, dst netip.AddrPort }
type serverFlow struct {
	key  flowKey
	conn net.Conn
	last atomic.Int64
}

func (s *Server) serveUDP(parent context.Context, user string, stream net.Conn) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	var mu sync.Mutex
	flows := map[flowKey]*serverFlow{}
	var workers sync.WaitGroup
	writer := make(chan struct{}, 1)
	writer <- struct{}{}
	remove := func(f *serverFlow) {
		mu.Lock()
		if flows[f.key] == f {
			delete(flows, f.key)
		}
		mu.Unlock()
		_ = f.conn.Close()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		tick := time.NewTicker(min(time.Second, s.config.UDPIdleTimeout))
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				mu.Lock()
				expired := []*serverFlow{}
				for _, f := range flows {
					if time.Since(time.Unix(0, f.last.Load())) >= s.config.UDPIdleTimeout {
						delete(flows, f.key)
						expired = append(expired, f)
					}
				}
				mu.Unlock()
				for _, f := range expired {
					_ = f.conn.Close()
				}
			}
		}
	}()
	defer func() {
		cancel()
		mu.Lock()
		all := make([]*serverFlow, 0, len(flows))
		for _, f := range flows {
			all = append(all, f)
		}
		clear(flows)
		mu.Unlock()
		for _, f := range all {
			_ = f.conn.Close()
		}
		workers.Wait()
	}()
	for {
		d, e := wire.ReadUDP(stream, true)
		if e != nil {
			return
		}
		key := flowKey{d.Source, d.Destination}
		mu.Lock()
		f := flows[key]
		full := len(flows) >= s.config.MaxFlows
		mu.Unlock()
		if f == nil {
			if full {
				return
			}
			dial, cancelDial := context.WithTimeout(ctx, s.config.ConnectTimeout)
			target, e := s.config.DialUDP(dial, user, d.Destination.String())
			cancelDial()
			if e != nil {
				return
			}
			f = &serverFlow{key: key, conn: target}
			f.last.Store(time.Now().UnixNano())
			mu.Lock()
			flows[key] = f
			mu.Unlock()
			workers.Add(1)
			go func(f *serverFlow) {
				defer workers.Done()
				defer remove(f)
				b := make([]byte, wire.MaxPayload)
				for {
					n, e := f.conn.Read(b)
					if e != nil {
						return
					}
					f.last.Store(time.Now().UnixNano())
					frame, e := wire.EncodeUDP(wire.Datagram{Source: f.key.dst, Destination: f.key.src, Payload: b[:n]}, false)
					if e != nil {
						return
					}
					select {
					case <-writer:
					case <-ctx.Done():
						return
					}
					_ = stream.SetWriteDeadline(time.Now().Add(s.config.ConnectTimeout))
					_, e = stream.Write(frame)
					_ = stream.SetWriteDeadline(time.Time{})
					writer <- struct{}{}
					if e != nil {
						cancel()
						return
					}
				}
			}(f)
		}
		f.last.Store(time.Now().UnixNano())
		_ = f.conn.SetWriteDeadline(time.Now().Add(s.config.ConnectTimeout))
		n, e := f.conn.Write(d.Payload)
		if e != nil || n != len(d.Payload) {
			remove(f)
		}
	}
}

type udpMux struct {
	c        *Client
	s        *clientSession
	conn     net.Conn
	mu       sync.Mutex
	terminal error
	flows    map[netip.AddrPort]*Packet
	active   *Packet
	next     uint32
	gate     chan struct{}
	writes   chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	workers  sync.WaitGroup
}
type Packet struct {
	mux            *udpMux
	source, target netip.AddrPort
	rx             chan wire.Datagram
	done           chan struct{}
	once           sync.Once
	mu             sync.Mutex
	rd, wd         time.Time
	changed        chan struct{}
	err            error
	last           atomic.Int64
}

func (c *Client) OpenPacket(ctx context.Context, target netip.AddrPort) (net.PacketConn, error) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if !target.IsValid() || target.Port() == 0 || target.Addr().Zone() != "" || target.Addr().IsUnspecified() || target.Addr().IsMulticast() {
		return nil, failure(Config, nil)
	}
	s, e := c.acquire(ctx)
	if e != nil {
		return nil, e
	}
	for {
		s.mu.Lock()
		if s.udp != nil {
			m := s.udp
			s.mu.Unlock()
			return m.open(target)
		}
		if wait := s.udpOpening; wait != nil {
			s.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-s.ctx.Done():
				return nil, failure(Unavailable, nil)
			}
		}
		s.udpOpening = make(chan struct{})
		s.mu.Unlock()
		conn, e := c.openSession(ctx, s, "_udp2")
		s.mu.Lock()
		close(s.udpOpening)
		s.udpOpening = nil
		if e != nil {
			s.mu.Unlock()
			return nil, e
		}
		life, cancel := context.WithCancel(s.ctx)
		m := &udpMux{c: c, s: s, conn: conn, ctx: life, cancel: cancel, flows: map[netip.AddrPort]*Packet{}, next: 1024, gate: make(chan struct{}, 1), writes: make(chan struct{}, 64)}
		m.gate <- struct{}{}
		s.udp = m
		s.mu.Unlock()
		c.mu.Lock()
		if c.ctx.Err() != nil {
			c.mu.Unlock()
			_ = conn.Close()
			cancel()
			return nil, failure(Closed, nil)
		}
		c.workers.Add(1)
		c.mu.Unlock()
		go func() { defer c.workers.Done(); m.run() }()
		return m.open(target)
	}
}
func (m *udpMux) open(target netip.AddrPort) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.terminal != nil {
		return nil, m.terminal
	}
	if m.ctx.Err() != nil {
		return nil, failure(Unavailable, nil)
	}
	if len(m.flows) >= m.c.config.MaxFlows || m.next >= 65535 {
		return nil, failure(Capacity, nil)
	}
	// Do not recycle a retired flow's source port on this byte stream. Late
	// responses must never be delivered to a later association for that target.
	m.next++
	source := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(m.next))
	p := &Packet{mux: m, source: source, target: target, rx: make(chan wire.Datagram, 16), done: make(chan struct{}), changed: make(chan struct{})}
	p.last.Store(time.Now().UnixNano())
	m.flows[source] = p
	return p, nil
}
func (m *udpMux) run() {
	reason := failure(Unavailable, nil)
	defer func() {
		// Stop admission and retire all associations atomically, before any
		// stream close or child failure can block. A caller may retain this
		// mux even after the session publishes a replacement.
		m.mu.Lock()
		m.terminal = reason
		all := make([]*Packet, 0, len(m.flows))
		for _, p := range m.flows {
			all = append(all, p)
		}
		clear(m.flows)
		m.mu.Unlock()
		_ = m.conn.Close()
		m.s.mu.Lock()
		if m.s.udp == m {
			m.s.udp = nil
		}
		m.s.mu.Unlock()
		for _, p := range all {
			p.fail(reason)
		}
		m.cancel()
		m.workers.Wait()
	}()
	stop := context.AfterFunc(m.ctx, func() { _ = m.conn.Close() })
	defer stop()
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		t := time.NewTicker(min(time.Second, m.c.config.UDPIdleTimeout))
		defer t.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-t.C:
				m.mu.Lock()
				expired := []*Packet{}
				for _, p := range m.flows {
					if time.Since(time.Unix(0, p.last.Load())) >= m.c.config.UDPIdleTimeout {
						expired = append(expired, p)
					}
				}
				m.mu.Unlock()
				for _, p := range expired {
					p.fail(failure(Unavailable, nil))
				}
			}
		}
	}()
	for {
		d, e := wire.ReadUDP(m.conn, false)
		if e != nil {
			if errors.Is(e, wire.ErrFrame) || errors.Is(e, io.ErrUnexpectedEOF) {
				reason = failure(Framing, e)
			}
			return
		}
		m.mu.Lock()
		p := m.flows[d.Destination]
		m.mu.Unlock()
		if p == nil || d.Source != p.target {
			continue
		}
		select {
		case p.rx <- d:
			p.last.Store(time.Now().UnixNano())
		case <-p.done:
		default:
			p.fail(failure(Capacity, nil))
		}
	}
}
func (p *Packet) fail(e error) {
	p.once.Do(func() {
		p.mu.Lock()
		p.err = e
		close(p.done)
		p.mu.Unlock()
		p.mux.mu.Lock()
		delete(p.mux.flows, p.source)
		active := p.mux.active == p
		p.mux.mu.Unlock()
		if active {
			p.mux.cancel()
		}
	})
}
func (p *Packet) Close() error        { p.fail(net.ErrClosed); return nil }
func (p *Packet) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(p.source) }
func (p *Packet) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		d, changed, e := p.rd, p.changed, p.err
		p.mu.Unlock()
		if e != nil {
			return 0, nil, e
		}
		if !d.IsZero() && !time.Now().Before(d) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		expiry, stop := waitDeadline(d)
		select {
		case v := <-p.rx:
			stop()
			if len(v.Payload) > len(b) {
				return 0, nil, io.ErrShortBuffer
			}
			return copy(b, v.Payload), net.UDPAddrFromAddrPort(v.Source), nil
		case <-p.done:
			stop()
		case <-p.mux.ctx.Done():
			stop()
			return 0, nil, failure(Unavailable, nil)
		case <-changed:
			stop()
		case <-expiry:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}
func (p *Packet) WriteTo(b []byte, address net.Addr) (int, error) {
	a, ok := address.(*net.UDPAddr)
	if !ok || a == nil {
		return 0, failure(Config, nil)
	}
	target := a.AddrPort()
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if target != p.target {
		return 0, failure(Config, nil)
	}
	select {
	case p.mux.writes <- struct{}{}:
		defer func() { <-p.mux.writes }()
	default:
		return 0, failure(Capacity, nil)
	}
	frame, e := wire.EncodeUDP(wire.Datagram{Source: p.source, Destination: p.target, Payload: b}, true)
	if e != nil {
		return 0, failure(Framing, e)
	}
	for {
		p.mu.Lock()
		d, changed, e := p.wd, p.changed, p.err
		p.mu.Unlock()
		if e != nil {
			return 0, e
		}
		if !d.IsZero() && !time.Now().Before(d) {
			return 0, os.ErrDeadlineExceeded
		}
		expiry, stop := waitDeadline(d)
		select {
		case <-p.mux.gate:
			stop()
			defer func() { p.mux.gate <- struct{}{} }()
			p.mu.Lock()
			d, e = p.wd, p.err
			p.mu.Unlock()
			if e != nil {
				return 0, e
			}
			if d.IsZero() {
				d = time.Now().Add(p.mux.c.config.ConnectTimeout)
			}
			p.mux.mu.Lock()
			p.mu.Lock()
			d, e = p.wd, p.err
			p.mu.Unlock()
			if e != nil {
				p.mux.mu.Unlock()
				return 0, e
			}
			if d.IsZero() {
				d = time.Now().Add(p.mux.c.config.ConnectTimeout)
			}
			p.mux.active = p
			_ = p.mux.conn.SetWriteDeadline(d)
			p.mux.mu.Unlock()
			n, e := p.mux.conn.Write(frame)
			p.mux.mu.Lock()
			p.mux.active = nil
			_ = p.mux.conn.SetWriteDeadline(time.Time{})
			p.mux.mu.Unlock()
			if e != nil || n != len(frame) {
				if e == nil {
					e = io.ErrShortWrite
				}
				p.mux.cancel()
				return 0, e
			}
			p.last.Store(time.Now().UnixNano())
			return len(b), nil
		case <-p.done:
			stop()
		case <-p.mux.ctx.Done():
			stop()
			return 0, failure(Unavailable, nil)
		case <-changed:
			stop()
		case <-expiry:
			return 0, os.ErrDeadlineExceeded
		}
	}
}
func (p *Packet) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.rd = t
	p.wd = t
	close(p.changed)
	p.changed = make(chan struct{})
	e := p.err
	p.mu.Unlock()
	p.updateWriteDeadline(t)
	return e
}
func (p *Packet) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rd = t
	close(p.changed)
	p.changed = make(chan struct{})
	return p.err
}
func (p *Packet) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.wd = t
	close(p.changed)
	p.changed = make(chan struct{})
	e := p.err
	p.mu.Unlock()
	p.updateWriteDeadline(t)
	return e
}

func (p *Packet) updateWriteDeadline(t time.Time) {
	p.mux.mu.Lock()
	defer p.mux.mu.Unlock()
	if p.mux.active == p {
		_ = p.mux.conn.SetWriteDeadline(t)
	}
}
