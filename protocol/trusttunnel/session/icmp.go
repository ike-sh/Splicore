package session

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
)

// EchoBackend is supplied by the Core's socket/policy owner. Its context must
// interrupt all raw I/O. A missing backend is explicit ICMP unavailability.
type EchoBackend func(context.Context, string, wire.EchoRequest) (wire.EchoReply, error)
type echoKey struct {
	address string
	id, seq uint16
}

func requestKey(r wire.EchoRequest) echoKey {
	return echoKey{r.Destination.Unmap().String(), r.ID, r.Sequence}
}
func replyKey(r wire.EchoReply) echoKey { return echoKey{r.Source.Unmap().String(), r.ID, r.Sequence} }
func (s *Server) serveEcho(parent context.Context, user string, stream net.Conn) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	requests := make(chan wire.EchoRequest, 64)
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	var mu sync.Mutex
	pending := map[echoKey]bool{}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case r := <-requests:
					request, cancelRequest := context.WithTimeout(ctx, 3*time.Second)
					reply, e := s.config.Echo(request, user, r)
					cancelRequest()
					mu.Lock()
					delete(pending, requestKey(r))
					mu.Unlock()
					if e != nil {
						cancel()
						return
					}
					if replyKey(reply) != requestKey(r) {
						continue
					}
					b, e := wire.EncodeEchoReply(reply)
					if e != nil {
						continue
					}
					select {
					case <-gate:
					case <-ctx.Done():
						return
					}
					_ = stream.SetWriteDeadline(time.Now().Add(s.config.ConnectTimeout))
					_, e = stream.Write(b)
					_ = stream.SetWriteDeadline(time.Time{})
					gate <- struct{}{}
					if e != nil {
						cancel()
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	defer func() { cancel(); workers.Wait() }()
	for {
		var b [23]byte
		if _, e := io.ReadFull(stream, b[:]); e != nil {
			return
		}
		r, e := wire.DecodeEchoRequest(b[:])
		if e != nil {
			return
		}
		key := requestKey(r)
		mu.Lock()
		full := len(pending) >= 68
		duplicate := pending[key]
		if !full && !duplicate {
			pending[key] = true
		}
		mu.Unlock()
		if full || duplicate {
			return
		}
		select {
		case requests <- r:
		case <-ctx.Done():
			return
		}
	}
}

type echoResult struct {
	reply wire.EchoReply
	err   error
}
type echoPending struct {
	request wire.EchoRequest
	result  chan echoResult
}
type echoMux struct {
	s       *clientSession
	conn    net.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	pending map[echoKey]echoPending
	// Never reuse a wire ID/sequence pair within this stream, including after
	// timeout. A late reply cannot satisfy a later caller using the same ID.
	next uint64
	gate chan struct{}
}

func (c *Client) echoSession(ctx context.Context, s *clientSession) (*echoMux, error) {
	for {
		s.mu.Lock()
		if s.echo != nil {
			m := s.echo
			s.mu.Unlock()
			return m, nil
		}
		if wait := s.echoOpening; wait != nil {
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
		s.echoOpening = make(chan struct{})
		s.mu.Unlock()
		conn, e := c.openSession(ctx, s, "_icmp")
		s.mu.Lock()
		close(s.echoOpening)
		s.echoOpening = nil
		if e != nil {
			s.mu.Unlock()
			return nil, failure(ICMPUnavailable, e)
		}
		life, cancel := context.WithCancel(s.ctx)
		m := &echoMux{s: s, conn: conn, ctx: life, cancel: cancel, pending: map[echoKey]echoPending{}, gate: make(chan struct{}, 1)}
		m.gate <- struct{}{}
		s.echo = m
		s.mu.Unlock()
		c.mu.Lock()
		if c.ctx.Err() != nil {
			c.mu.Unlock()
			cancel()
			_ = conn.Close()
			return nil, failure(Closed, nil)
		}
		c.workers.Add(1)
		c.mu.Unlock()
		go func() { defer c.workers.Done(); m.run() }()
		return m, nil
	}
}
func (m *echoMux) run() {
	defer func() {
		m.cancel()
		_ = m.conn.Close()
		m.s.mu.Lock()
		if m.s.echo == m {
			m.s.echo = nil
		}
		m.s.mu.Unlock()
		m.mu.Lock()
		clear(m.pending)
		m.mu.Unlock()
	}()
	stop := context.AfterFunc(m.ctx, func() { _ = m.conn.Close() })
	defer stop()
	for {
		var b [22]byte
		if _, e := io.ReadFull(m.conn, b[:]); e != nil {
			return
		}
		r, e := wire.DecodeEchoReply(b[:])
		if e != nil {
			return
		}
		m.mu.Lock()
		p, ok := m.pending[replyKey(r)]
		if ok {
			delete(m.pending, replyKey(r))
			r.ID, r.Sequence = p.request.ID, p.request.Sequence
			p.result <- echoResult{reply: r}
		}
		m.mu.Unlock()
	}
}
func (c *Client) Echo(ctx context.Context, r wire.EchoRequest) (wire.EchoReply, error) {
	_, e := wire.EncodeEchoRequest(r)
	if e != nil {
		return wire.EchoReply{}, failure(Config, e)
	}
	s, e := c.acquire(ctx)
	if e != nil {
		return wire.EchoReply{}, e
	}
	m, e := c.echoSession(ctx, s)
	if e != nil {
		return wire.EchoReply{}, e
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.HealthTimeout)
	defer cancel()
	result := make(chan echoResult, 1)
	m.mu.Lock()
	if m.ctx.Err() != nil || len(m.pending) >= 128 || m.next >= 1<<32 {
		m.mu.Unlock()
		return wire.EchoReply{}, failure(Capacity, nil)
	}
	onWire := r
	onWire.ID, onWire.Sequence = uint16(m.next>>16), uint16(m.next)
	m.next++
	key := requestKey(onWire)
	m.pending[key] = echoPending{r, result}
	m.mu.Unlock()
	b, _ := wire.EncodeEchoRequest(onWire)
	defer func() {
		m.mu.Lock()
		if m.pending[key].result == result {
			delete(m.pending, key)
		}
		m.mu.Unlock()
	}()
	select {
	case <-m.gate:
	case <-ctx.Done():
		return wire.EchoReply{}, ctx.Err()
	case <-m.ctx.Done():
		return wire.EchoReply{}, failure(ICMPUnavailable, nil)
	}
	deadline, _ := ctx.Deadline()
	_ = m.conn.SetWriteDeadline(deadline)
	_, e = m.conn.Write(b)
	_ = m.conn.SetWriteDeadline(time.Time{})
	m.gate <- struct{}{}
	if e != nil {
		m.cancel()
		return wire.EchoReply{}, failure(ICMPUnavailable, e)
	}
	select {
	case v := <-result:
		return v.reply, v.err
	case <-ctx.Done():
		return wire.EchoReply{}, ctx.Err()
	case <-m.ctx.Done():
		return wire.EchoReply{}, failure(ICMPUnavailable, nil)
	}
}
