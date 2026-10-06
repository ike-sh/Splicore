// Package packetio adapts a bounded, independently owned datagram queue to
// net.PacketConn. Protocol integrations supply their encoder/send callback.
package packetio

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type item struct {
	payload []byte
	address net.Addr
}
type Queue struct {
	ctx    context.Context
	cancel context.CancelFunc
	local  net.Addr
	// send must honor cancellation, or transfer only owned bytes to a bounded
	// parent-owned writer before waiting. It must not retain caller scratch.
	send        func(context.Context, []byte, net.Addr) error
	in          chan item
	rmu, mu     sync.Mutex
	writable    chan struct{}
	active      *writeOperation
	read, write time.Time
	changed     chan struct{}
}

type writeOperation struct {
	cancel context.CancelCauseFunc
	timer  *time.Timer
}

func New(ctx context.Context, local net.Addr, send func(context.Context, []byte, net.Addr) error) *Queue {
	ctx, cancel := context.WithCancel(ctx)
	q := &Queue{ctx: ctx, cancel: cancel, local: local, send: send, in: make(chan item, 64), changed: make(chan struct{}), writable: make(chan struct{}, 1)}
	q.writable <- struct{}{}
	return q
}

// Deliver copies decoder-owned bytes before enqueuing. Protocol dispatchers
// may reuse their frame immediately. The queue never closes its data channel.
func (q *Queue) Deliver(payload []byte, address net.Addr) {
	v := item{bytes.Clone(payload), address}
	select {
	case <-q.ctx.Done():
	case q.in <- v:
	default:
	}
}
func (q *Queue) ReadFrom(b []byte) (int, net.Addr, error) {
	q.rmu.Lock()
	defer q.rmu.Unlock()
	for {
		q.mu.Lock()
		deadline, changed := q.read, q.changed
		q.mu.Unlock()
		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			if !deadline.After(time.Now()) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		select {
		case <-q.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-expired:
			return 0, nil, os.ErrDeadlineExceeded
		case v := <-q.in:
			if timer != nil {
				timer.Stop()
			}
			if len(b) < len(v.payload) {
				return 0, nil, io.ErrShortBuffer
			}
			return copy(b, v.payload), v.address, nil
		}
	}
}
func (q *Queue) WriteTo(b []byte, address net.Addr) (int, error) {
	if err := q.acquireWrite(); err != nil {
		return 0, err
	}
	defer func() { q.writable <- struct{}{} }()
	ctx, cancel := context.WithCancelCause(q.ctx)
	op := &writeOperation{cancel: cancel}
	q.mu.Lock()
	q.active = op
	q.armWrite(op)
	q.mu.Unlock()
	defer func() {
		q.mu.Lock()
		if op.timer != nil {
			op.timer.Stop()
		}
		q.active = nil
		q.mu.Unlock()
		cancel(nil)
	}()
	var err error
	if ctx.Err() == nil {
		err = q.send(ctx, b, address)
		// A successful send is its definitive completion result. Cancellation
		// racing an already completed wire commit must not turn it into failure.
		if err == nil {
			return len(b), nil
		}
	}
	if cause := context.Cause(ctx); cause != nil {
		if cause == os.ErrDeadlineExceeded {
			return 0, cause
		}
		return 0, net.ErrClosed
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Admission is cancellable too: a second writer must not get stuck behind
// another WriteTo after Close or a deadline update.
func (q *Queue) acquireWrite() error {
	for {
		q.mu.Lock()
		deadline, changed := q.write, q.changed
		q.mu.Unlock()
		if q.ctx.Err() != nil {
			return net.ErrClosed
		}
		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			if !deadline.After(time.Now()) {
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		select {
		case <-q.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-expired:
			// Re-read: a concurrent reset may have replaced this deadline.
		case <-q.writable:
			if timer != nil {
				timer.Stop()
			}
			return nil
		}
	}
}

// q.mu protects timer replacement and expiry against deadline resets. An old
// callback rechecks the current timestamp instead of expiring a cleared timer.
func (q *Queue) armWrite(op *writeOperation) {
	if op.timer != nil {
		op.timer.Stop()
	}
	if q.write.IsZero() {
		return
	}
	if !q.write.After(time.Now()) {
		op.cancel(os.ErrDeadlineExceeded)
		return
	}
	op.timer = time.AfterFunc(time.Until(q.write), func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		if q.active == op && !q.write.IsZero() && !q.write.After(time.Now()) {
			op.cancel(os.ErrDeadlineExceeded)
		}
	})
}
func (q *Queue) Close() error             { q.cancel(); return nil }
func (q *Queue) Context() context.Context { return q.ctx }
func (q *Queue) LocalAddr() net.Addr      { return q.local }
func (q *Queue) set(t time.Time, read, write bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if read {
		q.read = t
	}
	if write {
		q.write = t
		if q.active != nil {
			q.armWrite(q.active)
		}
	}
	close(q.changed)
	q.changed = make(chan struct{})
	return nil
}
func (q *Queue) SetDeadline(t time.Time) error      { return q.set(t, true, true) }
func (q *Queue) SetReadDeadline(t time.Time) error  { return q.set(t, true, false) }
func (q *Queue) SetWriteDeadline(t time.Time) error { return q.set(t, false, true) }
