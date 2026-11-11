package native

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
)

// The runtime owns one UDP listener; each authenticated source owns a bounded
// queue and one target socket. A map lookup routes packets to the current object.
// Only that object's worker can remove it, including after an endpoint is reused.
type snellQUICProxy struct {
	mu      sync.Mutex
	packet  net.PacketConn
	key     *wire.Key
	dialer  *underlay.Dialer
	total   *traffic.Counter
	ctx     context.Context
	cancel  context.CancelFunc
	flows   map[netip.AddrPort]*snellQUICFlow
	wg      sync.WaitGroup
	once    sync.Once
	allowed func() bool
}
type snellQUICFlow struct {
	queue chan []byte
	dst   access.Endpoint
	peer  *net.UDPAddr
}

func newSnellQUICProxy(p net.PacketConn, k *wire.Key, d *underlay.Dialer, total *traffic.Counter, allowed func() bool) *snellQUICProxy {
	ctx, cancel := context.WithCancel(context.Background())
	s := &snellQUICProxy{packet: p, key: k, dialer: d, total: total, allowed: allowed, ctx: ctx, cancel: cancel, flows: map[netip.AddrPort]*snellQUICFlow{}}
	s.wg.Go(s.read)
	return s
}

func (s *snellQUICProxy) read() {
	b := make([]byte, 65535)
	for {
		n, a, err := s.packet.ReadFrom(b)
		if err != nil {
			return
		}
		peer, ok := a.(*net.UDPAddr)
		if !ok || n == 0 || n > 65507 || !s.allowed() {
			continue
		}
		id := peer.AddrPort()
		var dst access.Endpoint
		payload := b[:n]
		protected := !wire.QUICRaw(payload)
		if protected {
			dst, payload, err = wire.UnprotectQUIC(s.key, payload)
			if err != nil {
				continue
			}
		}
		s.mu.Lock()
		f := s.flows[id]
		if f == nil && protected && len(s.flows) < 128 && s.ctx.Err() == nil {
			f = &snellQUICFlow{queue: make(chan []byte, 32), dst: dst, peer: net.UDPAddrFromAddrPort(id)}
			s.flows[id] = f
			s.wg.Go(func() { s.serve(id, f) })
		}
		// Repeated protected Initials cannot change an authenticated destination.
		if f != nil && (!protected || dst == f.dst) {
			select {
			case f.queue <- append([]byte(nil), payload...):
			default:
			}
		}
		s.mu.Unlock()
	}
}

func (s *snellQUICProxy) serve(id netip.AddrPort, f *snellQUICFlow) {
	defer func() {
		s.mu.Lock()
		if s.flows[id] == f {
			delete(s.flows, id)
		}
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	admission, done := context.WithTimeout(ctx, 5*time.Second)
	c, err := s.dialer.DialContext(admission, "udp", net.JoinHostPort(f.dst.Host, portString(f.dst.Port)))
	done()
	if err != nil {
		return
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	release := traffic.Open(false, s.total)
	defer release()
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	var reader sync.WaitGroup
	reader.Go(func() {
		defer cancel()
		buf := make([]byte, 65535)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			if _, err = s.packet.WriteTo(buf[:n], f.peer); err != nil {
				return
			}
			traffic.CountDownload(n, s.total)
		}
	})
	defer func() { _ = c.Close(); reader.Wait() }()
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-f.queue:
			_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err = c.Write(p); err != nil {
				return
			}
			traffic.CountUpload(len(p), s.total)
		}
	}
}

func (s *snellQUICProxy) Close() { s.once.Do(func() { s.cancel(); _ = s.packet.Close(); s.wg.Wait() }) }
