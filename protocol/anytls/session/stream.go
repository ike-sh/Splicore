package session

import (
	"context"
	"io"
	"net"
	"os"
	"time"

	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

type Stream struct {
	session                     *Session
	id                          uint32
	queue                       [][]byte
	offset, buffered            int
	changed                     chan struct{}
	writeOrder                  chan struct{}
	closed                      bool
	err                         error
	ackDone                     bool
	ackErr                      error
	readDeadline, writeDeadline time.Time
	ctx                         context.Context
	cancel                      context.CancelFunc
}

func (st *Stream) ID() uint32               { return st.id }
func (st *Stream) Context() context.Context { return st.ctx }
func (st *Stream) signalLocked()            { close(st.changed); st.changed = make(chan struct{}) }
func (st *Stream) terminateLocked(err error, drain bool) {
	if st.closed {
		return
	}
	st.closed, st.err = true, err
	st.cancel()
	if !drain {
		st.session.buffered -= st.buffered
		st.buffered = 0
		st.queue = nil
		st.offset = 0
	}
	st.signalLocked()
}

func wait(ch <-chan struct{}, done <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-ch:
			return nil
		case <-done:
			return net.ErrClosed
		}
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-done:
		return net.ErrClosed
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

func (st *Stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s := st.session
	for {
		s.mu.Lock()
		if !st.readDeadline.IsZero() && !st.readDeadline.After(time.Now()) {
			s.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if len(st.queue) > 0 {
			n := copy(b, st.queue[0][st.offset:])
			st.offset += n
			st.buffered -= n
			s.buffered -= n
			if st.offset == len(st.queue[0]) {
				st.queue[0] = nil
				st.queue = st.queue[1:]
				st.offset = 0
			}
			s.mu.Unlock()
			return n, nil
		}
		if st.closed {
			err := st.err
			s.mu.Unlock()
			return 0, err
		}
		ch, deadline := st.changed, st.readDeadline
		s.mu.Unlock()
		if err := wait(ch, s.done, deadline); err != nil {
			if err == net.ErrClosed {
				continue
			}
			return 0, err
		}
	}
}

func (st *Stream) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s := st.session
	// Serialize application writes on this stream without holding metadata or
	// the session output channel while another stream waits to write.
	for {
		s.mu.Lock()
		closed, deadline, ch := st.closed, st.writeDeadline, st.changed
		s.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerC = timer.C
		}
		acquired := false
		select {
		case <-st.writeOrder:
			acquired = true
		case <-ch:
		case <-s.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case <-timerC:
			return 0, os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if acquired {
			break
		}
	}
	defer func() { st.writeOrder <- struct{}{} }()
	n := 0
	for len(b) > 0 {
		size := min(len(b), wire.MaxPayload)
		if err := s.send(st, wire.Frame{Command: wire.Data, Stream: st.id, Payload: b[:size]}); err != nil {
			return n, err
		}
		n += size
		b = b[size:]
	}
	return n, nil
}

// CloseWrite is the protocol's full logical stream close, not TCP half-close.
func (st *Stream) CloseWrite() error { return st.Close() }
func (st *Stream) CloseRead() error  { return st.Close() }
func (st *Stream) Close() error {
	s := st.session
	s.mu.Lock()
	send := !st.closed && !s.closed
	if st.closed {
		// A remote FIN may leave bytes available for Read. Explicit local Close
		// releases that retained queue without generating a reply FIN.
		s.buffered -= st.buffered
		st.buffered = 0
		st.queue = nil
		st.offset = 0
	} else {
		st.terminateLocked(net.ErrClosed, false)
	}
	s.removeLocked(st.id)
	s.signal()
	s.mu.Unlock()
	s.refreshWriteDeadline(st)
	if send {
		return s.send(nil, wire.Frame{Command: wire.Finish, Stream: st.id})
	}
	return nil
}

// Accept reports the independently performed destination connect result.
func (st *Stream) Accept(err error) error {
	s := st.session
	s.mu.Lock()
	if s.client || st.closed || st.ackDone {
		s.mu.Unlock()
		return wire.ErrProtocol
	}
	st.ackDone = true
	version := s.version
	s.mu.Unlock()
	var result error
	if version == 2 {
		var data []byte
		if err != nil {
			data = []byte("destination unavailable")
		}
		result = s.send(st, wire.Frame{Command: wire.OpenResult, Stream: st.id, Payload: data})
	}
	if err != nil {
		_ = st.Close()
	}
	return result
}

func (st *Stream) waitOpen(ctx context.Context) error {
	s := st.session
	negotiation := time.NewTimer(s.cfg.NegotiationWait)
	defer negotiation.Stop()
	limit := time.NewTimer(s.cfg.OpenTimeout)
	defer limit.Stop()
	unknownDone := false
	for {
		s.mu.Lock()
		if st.ackErr != nil {
			err := st.ackErr
			s.mu.Unlock()
			return err
		}
		if st.ackDone {
			s.mu.Unlock()
			return nil
		}
		if st.closed {
			err := st.err
			s.mu.Unlock()
			return err
		}
		if s.cfg.Version == 1 || s.version == 1 && (unknownDone || s.settingsDone) {
			s.mu.Unlock()
			return nil
		}
		ch, sessionChanged := st.changed, s.changed
		s.mu.Unlock()
		select {
		case <-ch:
		case <-sessionChanged:
		case <-negotiation.C:
			unknownDone = true
		case <-limit.C:
			return os.ErrDeadlineExceeded
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return net.ErrClosed
		}
	}
}

func (st *Stream) LocalAddr() net.Addr  { return st.session.conn.LocalAddr() }
func (st *Stream) RemoteAddr() net.Addr { return st.session.conn.RemoteAddr() }
func (st *Stream) SetDeadline(t time.Time) error {
	s := st.session
	s.mu.Lock()
	st.readDeadline = t
	st.writeDeadline = t
	st.signalLocked()
	s.mu.Unlock()
	s.refreshWriteDeadline(st)
	return nil
}
func (st *Stream) SetReadDeadline(t time.Time) error {
	s := st.session
	s.mu.Lock()
	st.readDeadline = t
	st.signalLocked()
	s.mu.Unlock()
	return nil
}
func (st *Stream) SetWriteDeadline(t time.Time) error {
	s := st.session
	s.mu.Lock()
	st.writeDeadline = t
	st.signalLocked()
	s.mu.Unlock()
	s.refreshWriteDeadline(st)
	return nil
}

var _ net.Conn = (*Stream)(nil)
var _ io.ReadWriteCloser = (*Stream)(nil)
