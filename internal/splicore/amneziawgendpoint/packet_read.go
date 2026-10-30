package amneziawgendpoint

import (
	"errors"
	"net"
	"os"
	"time"
)

type packetRead struct {
	err error // first termination reason, protected by routedPacket.mu
}

func (p *routedPacket) stopReadTimerLocked() {
	p.readEpoch++
	if p.readTimer != nil {
		p.readTimer.Stop()
		p.readTimer = nil
	}
}

func (p *routedPacket) armReadTimerLocked() {
	p.stopReadTimerLocked()
	if p.readDeadline.IsZero() || len(p.reads) == 0 || p.closed {
		return
	}
	if !time.Now().Before(p.readDeadline) {
		p.expireReadsLocked()
		return
	}
	epoch := p.readEpoch
	p.readTimer = time.AfterFunc(time.Until(p.readDeadline), func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.readEpoch == epoch {
			p.readTimer = nil
			p.expireReadsLocked()
		}
	})
}

func (p *routedPacket) expireReadsLocked() {
	reason := error(os.ErrDeadlineExceeded)
	if p.endpoint.ctx.Err() != nil {
		reason = net.ErrClosed
	}
	for r := range p.reads {
		if r.err == nil {
			r.err = reason
		}
	}
}

func (p *routedPacket) readErrorLocked(r *packetRead) error {
	if r.err == nil {
		switch {
		case p.closed || p.endpoint.ctx.Err() != nil:
			r.err = net.ErrClosed
		case !p.readDeadline.IsZero() && !time.Now().Before(p.readDeadline):
			r.err = os.ErrDeadlineExceeded
		}
	}
	return r.err
}

func (p *routedPacket) beginRead() (*packetRead, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := &packetRead{}
	if err := p.readErrorLocked(r); err != nil {
		return nil, err
	}
	// Only pending transport I/O owns an underlying deadline timer. The final
	// completion disarms it, so Close itself never calls a deadline setter.
	if len(p.reads) == 0 {
		if err := p.PacketConn.SetReadDeadline(p.readDeadline); err != nil {
			return nil, err
		}
	}
	p.reads[r] = struct{}{}
	p.wg.Add(1)
	if len(p.reads) == 1 {
		p.armReadTimerLocked()
	}
	return r, nil
}

func (p *routedPacket) finishRead(r *packetRead, err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if reason := p.readErrorLocked(r); reason != nil {
		err = reason
	} else {
		// gVisor's timeout implements net.Error but does not unwrap the Go
		// deadline sentinel. Preserve standard PacketConn compatibility even
		// if a later deadline change precedes this completion's mutex lock.
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			err = os.ErrDeadlineExceeded
		}
	}
	delete(p.reads, r)
	if len(p.reads) == 0 {
		p.stopReadTimerLocked()
		_ = p.PacketConn.SetReadDeadline(time.Time{})
	}
	p.wg.Done()
	return err
}

func (p *routedPacket) ReadFrom(b []byte) (n int, address net.Addr, err error) {
	r, err := p.beginRead()
	if err != nil {
		return 0, nil, err
	}
	defer func() { err = p.finishRead(r, err) }()
	return p.PacketConn.ReadFrom(b)
}

func (p *routedPacket) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.endpoint.ctx.Err() != nil {
		return net.ErrClosed
	}
	return p.setReadDeadlineLocked(t)
}

func (p *routedPacket) setReadDeadlineLocked(t time.Time) error {
	if len(p.reads) != 0 {
		if err := p.PacketConn.SetReadDeadline(t); err != nil {
			return err
		}
	}
	p.readDeadline = t
	p.armReadTimerLocked()
	return nil
}
