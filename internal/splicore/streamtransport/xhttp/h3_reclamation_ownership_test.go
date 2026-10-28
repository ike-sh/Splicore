//go:build with_quic

package xhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Historical addresses can be reused by another socket. Retirement is a claim
// about this exact physical object and its ownership, not about its old port.
func h3ReclaimSocketError(h *h3Transport, s *h3Socket) error {
	h.mu.Lock()
	owned := h.sockets[s]
	c := s.owner
	carrierOwned, cached, refs, retiring := false, false, 0, true
	if c != nil {
		carrierOwned, cached, refs, retiring = h.carriers[c], h.cached == c, c.refs, c.retiring
	}
	q := s.conn
	h.mu.Unlock()
	if owned || carrierOwned || cached || refs != 0 || !retiring {
		return fmt.Errorf("socket=%p carrier=%p still owned: socket=%t carrier=%t cached=%t refs=%d retiring=%t", s, c, owned, carrierOwned, cached, refs, retiring)
	}
	if q == nil || q.Context().Err() == nil {
		return fmt.Errorf("socket=%p QUIC connection has not terminated", s)
	}
	if !errors.Is(s.packet.SetDeadline(time.Now()), net.ErrClosed) {
		return fmt.Errorf("socket=%p packet=%p is not closed", s, s.packet)
	}
	return nil
}

func h3ReclaimRetiredSocket(t *testing.T, h *h3Transport, s *h3Socket) {
	t.Helper()
	h3ReclaimAwait(t, func() bool { return h3ReclaimSocketError(h, s) == nil })
}

func h3ReclaimClosedPacket(t *testing.T, p net.PacketConn) {
	t.Helper()
	if !errors.Is(p.SetDeadline(time.Now()), net.ErrClosed) {
		t.Fatal("exact packet socket remains open", p)
	}
}

type h3ReclaimProbe struct {
	h       *h3Transport
	mu      sync.Mutex
	packets []*h3ReclaimTrackedPacket
	seq     atomic.Uint64
}

type h3ReclaimTrackedPacket struct {
	net.PacketConn
	probe                        *h3ReclaimProbe
	id, created                  uint64
	attached, closeOnce          sync.Once
	socket                       *h3Socket // Protected by probe.mu.
	closeDone                    chan struct{}
	closeErr                     error
	closeStart, closeEnd, retire atomic.Uint64
	readers                      atomic.Int32
}

func (p *h3ReclaimTrackedPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	p.attached.Do(func() {
		p.probe.h.mu.Lock()
		defer p.probe.h.mu.Unlock()
		for s := range p.probe.h.sockets {
			if s.packet == p {
				p.probe.mu.Lock()
				p.socket = s
				p.probe.mu.Unlock()
				return
			}
		}
	})
	return p.PacketConn.WriteTo(b, a)
}

func (p *h3ReclaimTrackedPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readers.Add(1)
	defer p.readers.Add(-1)
	return p.PacketConn.ReadFrom(b)
}

func (p *h3ReclaimTrackedPacket) Close() error {
	p.closeOnce.Do(func() {
		p.closeStart.Store(p.probe.seq.Add(1))
		p.closeErr = p.PacketConn.Close()
		p.closeEnd.Store(p.probe.seq.Add(1))
		close(p.closeDone)
	})
	return p.closeErr
}

func (o *h3ReclaimProbe) wrap(p net.PacketConn) *h3ReclaimTrackedPacket {
	id := o.seq.Add(1)
	tracked := &h3ReclaimTrackedPacket{PacketConn: p, probe: o, id: id, created: id, closeDone: make(chan struct{})}
	o.mu.Lock()
	o.packets = append(o.packets, tracked)
	o.mu.Unlock()
	return tracked
}

func (o *h3ReclaimProbe) snapshot() []*h3ReclaimTrackedPacket {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]*h3ReclaimTrackedPacket(nil), o.packets...)
}

func (o *h3ReclaimProbe) retired(p *h3ReclaimTrackedPacket) error {
	select {
	case <-p.closeDone:
	default:
		return fmt.Errorf("socket ID %d Close has not completed", p.id)
	}
	if p.closeErr != nil && !errors.Is(p.closeErr, net.ErrClosed) {
		return fmt.Errorf("socket ID %d Close: %w", p.id, p.closeErr)
	}
	o.mu.Lock()
	s := p.socket
	o.mu.Unlock()
	if s == nil {
		return fmt.Errorf("socket ID %d has no observed physical owner", p.id)
	}
	if err := h3ReclaimSocketError(o.h, s); err != nil {
		return err
	}
	if p.readers.Load() != 0 {
		return fmt.Errorf("socket ID %d UDP reader has not exited", p.id)
	}
	if p.retire.Load() == 0 {
		p.retire.CompareAndSwap(0, o.seq.Add(1))
	}
	return nil
}

func (o *h3ReclaimProbe) log(t *testing.T) {
	t.Helper()
	for _, p := range o.snapshot() {
		o.mu.Lock()
		s := p.socket
		o.mu.Unlock()
		t.Logf("socket_id=%d packet=%p socket=%p carrier=%p connection=%p local=%s created=%d close_start=%d close_end=%d retirement_observed=%d reader_active=%d", p.id, p, s, s.owner, s.conn, p.LocalAddr(), p.created, p.closeStart.Load(), p.closeEnd.Load(), p.retire.Load(), p.readers.Load())
	}
}

func h3ReclaimTrackClient(t *testing.T, cl *Client) *h3ReclaimProbe {
	t.Helper()
	o := &h3ReclaimProbe{}
	original := cl.security.PacketSocket
	cl.security.PacketSocket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, a, err := original(ctx)
		if err != nil {
			return p, a, err
		}
		return o.wrap(p), a, nil
	}
	// Create the fixed transport before the first UDP dial, so the packet probe
	// can capture its exact h3Socket and carrier during the first physical write.
	e, err := cl.pool.lease()
	if err != nil {
		t.Fatal(err)
	}
	o.h = e.transport.(*h3Transport)
	cl.pool.release(e)
	return o
}

func TestXHTTPH3ReclamationOwnership(t *testing.T) {
	f := newH3BodyFixture(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}, nil)
	o := &h3ReclaimProbe{h: f.transport}
	original := f.transport.socket
	f.transport.socket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, a, err := original(ctx)
		if err == nil {
			p = o.wrap(p)
		}
		return p, a, err
	}
	send := func() {
		r, _ := http.NewRequest(http.MethodPost, f.target, http.NoBody)
		resp, err := f.transport.RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	send()
	old := o.snapshot()[0]
	f.transport.mu.Lock()
	oldSocket := old.socket
	f.transport.mu.Unlock()
	oldSocket.conn.CloseWithError(0, "ownership positive control")
	h3ReclaimBound(t, f.transport, 0, 0, 0)
	if err := o.retired(old); err != nil {
		t.Fatal(err)
	}
	// The fixture allocates the replacement with ListenPacket on port zero.
	// Other fixtures may acquire the retired address; ownership is checked by
	// physical object identity regardless of either socket's local address.
	send()
	current := o.snapshot()[1]
	h3ReclaimBound(t, f.transport, 1, 1, 0)
	if old == current || old.socket == current.socket || old.socket.owner == current.socket.owner || old.socket.conn == current.socket.conn {
		t.Fatal("control did not create different physical owners")
	}
	f.transport.mu.Lock()
	cached := f.transport.cached == current.socket.owner
	f.transport.mu.Unlock()
	if !cached || current.socket.conn.Context().Err() != nil {
		t.Fatal("replacement is not the healthy cached connection")
	}
	if err := o.retired(old); err != nil {
		t.Fatal("old socket retained ownership after replacement", err)
	}
	send()
	if f.dials.Load() != 2 {
		t.Fatal("healthy replacement connection was not reused", f.dials.Load())
	}
	t.Logf("ownership_positive=true old_id=%d old_packet=%p old_socket=%p new_id=%d new_packet=%p new_socket=%p old_address=%s new_address=%s healthy_cached=true old_retired=true", old.id, old, old.socket, current.id, current, current.socket, old.LocalAddr(), current.LocalAddr())
	f.close()
	for _, packet := range o.snapshot() {
		if err := o.retired(packet); err != nil {
			t.Fatal(err)
		}
	}
	o.log(t)
}

func TestXHTTPH3ReclamationOracleNegativeControl(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	o := h3ReclaimTrackClient(t, cl)
	a, sa := h3DialSession(t, cl)
	front.connection(t)
	old := o.snapshot()[0]
	front.reject.Store(true)
	b, sb := h3DialSession(t, cl)
	front.connection(t)
	b.Close()
	h3AwaitTerminal(t, sb)
	h3ReclaimBound(t, o.h, 2, 2, 1)
	// Keep A's real response lease alive while B is the idle cache entry. The
	// same oracle used by the scale test must reject this retained old socket.
	if err := o.retired(old); err == nil {
		t.Fatal("oracle accepted an intentionally retained old carrier")
	} else {
		t.Logf("negative_control=retained_old_carrier detected=true old_id=%d reason=%v", old.id, err)
	}
	exchange(t, a, []byte("negative control still owns a live old carrier"))
	a.Close()
	h3AwaitTerminal(t, sa)
	h3ReclaimBound(t, o.h, 1, 1, 0)
	if err := o.retired(old); err != nil {
		t.Fatal("oracle did not accept normal retirement after releasing the lease", err)
	}
	cl.Close()
	h3ReclaimBound(t, o.h, 0, 0, 0)
	for _, packet := range o.snapshot() {
		if err := o.retired(packet); err != nil {
			t.Fatal(err)
		}
	}
	o.log(t)
}
