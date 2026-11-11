package wireguardendpoint

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
)

// routedPacket owns association I/O, including Core DNS during a logical write.
// Its mutex orders registration, completion, Close and deadline changes. Payload
// I/O never holds the mutex. The endpoint tracks the association's close barrier.
type routedPacket struct {
	net.PacketConn
	endpoint     *Endpoint
	local        netip.Addr
	release      func()
	mu           sync.Mutex
	closed       bool
	reads        map[*packetRead]struct{}
	readDeadline time.Time
	readTimer    *time.Timer
	readEpoch    uint64
	writes       map[*packetWrite]struct{}
	sends        int
	deadline     time.Time
	timer        *time.Timer
	epoch        uint64
	wg           sync.WaitGroup
	once         sync.Once
	err          error
}

type packetWrite struct {
	ctx     context.Context
	cancel  context.CancelFunc
	err     error // first termination reason, protected by routedPacket.mu
	sending bool
}

func newRoutedPacket(conn net.PacketConn, e *Endpoint, local netip.Addr) (*routedPacket, error) {
	p := &routedPacket{PacketConn: conn, endpoint: e, local: local, reads: make(map[*packetRead]struct{}), writes: make(map[*packetWrite]struct{})}
	release, err := e.pending.Track(p)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// Close may start as soon as Track returns. Publish release under the same
	// mutex used by Close so a concurrent endpoint shutdown cannot miss it.
	p.mu.Lock()
	if p.closed {
		release()
	} else {
		p.release = release
	}
	p.mu.Unlock()
	return p, nil
}

func (p *routedPacket) stopTimerLocked() {
	p.epoch++
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
}

func (p *routedPacket) cancelLocked(w *packetWrite, err error) {
	if w.err == nil {
		w.err = err
		w.cancel()
	}
}

// One timer per association covers all current writes. An epoch makes a stopped
// callback harmless even if it was already scheduled before extension/clear.
func (p *routedPacket) armTimerLocked() {
	p.stopTimerLocked()
	if p.deadline.IsZero() || len(p.writes) == 0 || p.closed {
		return
	}
	if !time.Now().Before(p.deadline) {
		p.expireLocked()
		return
	}
	epoch := p.epoch
	p.timer = time.AfterFunc(time.Until(p.deadline), func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.epoch == epoch {
			p.timer = nil
			p.expireLocked()
		}
	})
}

func (p *routedPacket) expireLocked() {
	reason := error(os.ErrDeadlineExceeded)
	if p.endpoint.ctx.Err() != nil {
		reason = net.ErrClosed
	}
	for w := range p.writes {
		p.cancelLocked(w, reason)
	}
}

func (p *routedPacket) beginWrite() (*packetWrite, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.endpoint.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if !p.deadline.IsZero() && !time.Now().Before(p.deadline) {
		return nil, os.ErrDeadlineExceeded
	}
	ctx, cancel := context.WithCancel(p.endpoint.ctx)
	w := &packetWrite{ctx: ctx, cancel: cancel}
	p.writes[w] = struct{}{}
	p.wg.Add(1)
	if len(p.writes) == 1 {
		p.armTimerLocked()
	}
	return w, nil
}

func (p *routedPacket) writeErrorLocked(w *packetWrite) error {
	if w.err == nil {
		switch {
		case p.closed || p.endpoint.ctx.Err() != nil:
			p.cancelLocked(w, net.ErrClosed)
		case !p.deadline.IsZero() && !time.Now().Before(p.deadline):
			p.cancelLocked(w, os.ErrDeadlineExceeded)
		}
	}
	return w.err
}

func (p *routedPacket) finishWrite(w *packetWrite, err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if reason := p.writeErrorLocked(w); reason != nil {
		err = reason
	}
	delete(p.writes, w)
	w.cancel()
	if w.sending {
		p.sends--
		if p.sends == 0 {
			// This is I/O completion cleanup, including after a real socket
			// Close. No transport deadline timer is retained by idle I/O.
			_ = p.PacketConn.SetWriteDeadline(time.Time{})
		}
	}
	if len(p.writes) == 0 {
		p.stopTimerLocked()
	}
	p.wg.Done()
	return err
}

func (p *routedPacket) WriteTo(b []byte, address net.Addr) (n int, err error) {
	w, err := p.beginWrite()
	if err != nil {
		return 0, err
	}
	defer func() { err = p.finishWrite(w, err) }()
	if address == nil {
		return 0, E.ErrInvalid
	}
	host, port, err := E.SplitEndpoint(address.String())
	if err != nil {
		return 0, err
	}
	target, local, err := p.endpoint.target(w.ctx, access.Endpoint{Host: host, Port: port})
	if err != nil {
		return 0, err
	}
	if local != p.local {
		return 0, errors.New("WireGuard UDP address family differs from association")
	}
	overhead := 28
	if local.Is6() {
		overhead = 48
	}
	if len(b) > p.endpoint.config.InnerMTU()-overhead {
		return 0, errors.New("WireGuard UDP payload exceeds inner MTU")
	}
	p.mu.Lock()
	err = p.writeErrorLocked(w)
	if err == nil && p.sends == 0 {
		err = p.PacketConn.SetWriteDeadline(p.deadline)
	}
	if err == nil {
		w.sending = true
		p.sends++
	}
	p.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return p.PacketConn.WriteTo(b, net.UDPAddrFromAddrPort(target))
}

func (p *routedPacket) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.endpoint.ctx.Err() != nil {
		return net.ErrClosed
	}
	return p.setWriteDeadlineLocked(t)
}

func (p *routedPacket) setWriteDeadlineLocked(t time.Time) error {
	if p.sends != 0 {
		if err := p.PacketConn.SetWriteDeadline(t); err != nil {
			return err
		}
	}
	p.deadline = t
	p.armTimerLocked()
	return nil
}

func (p *routedPacket) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.endpoint.ctx.Err() != nil {
		return net.ErrClosed
	}
	if err := p.setReadDeadlineLocked(t); err != nil {
		return err
	}
	return p.setWriteDeadlineLocked(t)
}

func (p *routedPacket) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.stopTimerLocked()
		p.stopReadTimerLocked()
		for r := range p.reads {
			if p.readErrorLocked(r) == nil {
				r.err = net.ErrClosed
			}
		}
		for w := range p.writes {
			if p.writeErrorLocked(w) == nil {
				p.cancelLocked(w, net.ErrClosed)
			}
		}
		p.closed = true
		release := p.release
		p.release = nil
		p.mu.Unlock()
		// ListenUDP creates a distinct gVisor UDP endpoint for this association.
		// Its Close notifies readable/writable waiters without expiring deadlines
		// or closing the shared WireGuard bind, Device, TUN or IP stack.
		p.err = p.PacketConn.Close()
		p.wg.Wait()
		if release != nil {
			release()
		}
	})
	return p.err
}
