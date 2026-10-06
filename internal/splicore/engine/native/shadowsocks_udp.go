package native

import (
	"context"
	"math"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks/wire"
)

type shadowsocksAssociationID struct {
	user    int
	session uint64
	source  string
	target  string
}

func (h *shadowsocksHandle) receive() {
	defer h.workers.Done()
	b := make([]byte, 65535)
	for {
		n, source, e := h.packet.ReadFrom(b)
		if e != nil {
			h.running.Store(false)
			return
		}
		if !h.admitted.Load() {
			continue
		}
		now := time.Now()
		p, e := wire.DecodePacket(h.keys, h.identity, b[:n], false, 0, h.replay.salts, now)
		if e != nil {
			continue
		}
		if h.keys[p.User].Method.Edition == "2022" {
			if e = h.replay.packets.Check(h.keys[p.User], p, now); e != nil {
				continue
			}
		}
		// Each destination owns a protected connected UDP socket, including DNS
		// and address-family selection. It cannot share another target's socket.
		id := shadowsocksAssociationID{user: p.User, session: p.Session, target: net.JoinHostPort(p.Destination.Host, portString(p.Destination.Port))}
		if h.keys[p.User].Method.Edition == "2017" {
			id.source = source.String()
		}
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			return
		}
		s := h.sessions[id]
		if s == nil {
			if len(h.sessions) >= 128 {
				h.mu.Unlock()
				continue
			}
			session, e := wire.SessionID()
			if e != nil {
				h.mu.Unlock()
				continue
			}
			child, cancel := context.WithCancel(h.ctx)
			s = &shadowsocksServerPacket{h: h, id: id, key: h.keys[p.User], session: session, queue: make(chan wire.Datagram, 8), done: make(chan struct{}), last: now, ctx: child, cancel: cancel}
			h.sessions[id] = s
			h.workers.Add(1)
			go h.routePacket(s, p.Destination)
		}
		if h.keys[p.User].Method.Edition == "2022" {
			// A validated source migration applies to every routed target of this
			// authenticated client session. Target idle expiry remains independent.
			for _, other := range h.sessions {
				if other.id.user == id.user && other.id.session == id.session {
					other.mu.Lock()
					other.source = source
					other.mu.Unlock()
				}
			}
		}
		h.mu.Unlock()
		s.mu.Lock()
		s.source = source
		s.last = now
		s.mu.Unlock()
		// Fixed queue; backpressure drops a datagram, never spawns another worker.
		select {
		case <-s.done:
		case s.queue <- p:
		default:
		}
	}
}
func (h *shadowsocksHandle) routePacket(s *shadowsocksServerPacket, dst access.Endpoint) {
	defer h.workers.Done()
	defer s.Close()
	remote, err := h.protected.DialContext(h.ctx, "udp", net.JoinHostPort(dst.Host, portString(dst.Port)))
	if err != nil {
		return
	}
	defer remote.Close()
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return
	default:
		s.target = remote
	}
	s.mu.Unlock()
	id := h.bindings[s.id.user]
	counters := []*traffic.Counter{&h.total.Counter, &h.users[id].Counter}
	release := traffic.Open(false, counters...)
	defer release()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer remote.Close()
		for {
			select {
			case <-s.done:
				return
			case p := <-s.queue:
				n, err := remote.Write(p.Payload)
				traffic.CountUpload(n, counters...)
				if err != nil {
					return
				}
			}
		}
	}()
	// This reader exclusively owns its scratch buffer. Encoding consumes it
	// synchronously; neither a queue nor another goroutine retains the backing array.
	b := make([]byte, 65535)
	responseAddr, err := netaddr.From(remote.RemoteAddr())
	if err == nil {
		for {
			n, err := remote.Read(b)
			if err != nil {
				break
			}
			if err = s.writePayload(b[:n], responseAddr); err != nil {
				break
			}
			traffic.CountDownload(n, counters...)
		}
	}
	s.Close()
	<-done
}
func (h *shadowsocksHandle) expire() {
	defer h.workers.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case now := <-ticker.C:
			h.mu.Lock()
			var expired []*shadowsocksServerPacket
			for _, s := range h.sessions {
				s.mu.Lock()
				idle := now.Sub(s.last) > 90*time.Second
				s.mu.Unlock()
				if idle {
					expired = append(expired, s)
				}
			}
			h.mu.Unlock()
			for _, s := range expired {
				s.Close()
			}
		}
	}
}

type shadowsocksServerPacket struct {
	h                *shadowsocksHandle
	id               shadowsocksAssociationID
	key              *wire.Key
	mu, wmu          sync.Mutex
	source           net.Addr
	target           net.Conn
	last             time.Time
	session, counter uint64
	queue            chan wire.Datagram
	done             chan struct{}
	once             sync.Once
	ctx              context.Context
	cancel           context.CancelFunc
}

func (s *shadowsocksServerPacket) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.cancel()
		s.mu.Lock()
		target := s.target
		s.mu.Unlock()
		if target != nil {
			_ = target.Close()
		}
		s.h.mu.Lock()
		if s.h.sessions[s.id] == s {
			delete(s.h.sessions, s.id)
		}
		s.h.mu.Unlock()
	})
	return nil
}
func (s *shadowsocksServerPacket) writePayload(b []byte, dst access.Endpoint) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	s.mu.Lock()
	source := s.source
	s.mu.Unlock()
	if udp, ok := source.(*net.UDPAddr); ok {
		snapshot := *udp
		snapshot.IP = append(net.IP(nil), udp.IP...)
		source = &snapshot
	}
	if source == nil {
		return net.ErrClosed
	}
	if s.counter == math.MaxUint64 {
		return wire.ErrCapacity
	}
	p, e := wire.EncodePacket([]*wire.Key{s.key}, wire.Datagram{Session: s.session, Packet: s.counter, ClientSession: s.id.session, Destination: dst, Payload: b}, true, time.Now())
	if e != nil {
		return e
	}
	if s.key.Method.Edition == "2017" {
		if e = s.h.replay.salts.Check(s.key, p[:s.key.Method.KeySize], time.Now()); e != nil {
			return e
		}
	}
	s.counter++
	e = s.h.packetWriter.SendTo(s.ctx, p, source)
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	return e
}
