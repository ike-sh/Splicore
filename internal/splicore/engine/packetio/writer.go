package packetio

import (
	"bytes"
	"context"
	"net"
)

type frameWrite struct {
	frame   []byte
	address net.Addr
	done    chan error
}

// Writer owns one worker for a parent transport whose send cannot observe a
// child's cancellation. Its unbuffered handoff preserves backpressure. Handoff
// commits one owned frame: a canceled caller may leave while that frame finishes,
// but cannot leave additional queued frames or retain caller/child state here.
// The parent must interrupt send on shutdown, then call Wait to join the worker.
type Writer struct {
	ctx      context.Context
	requests chan frameWrite
	done     chan struct{}
}

func NewWriter(parent context.Context, send func([]byte) error) *Writer {
	return NewAddressWriter(parent, func(b []byte, _ net.Addr) error { return send(b) })
}

// NewAddressWriter also transfers an immutable destination snapshot. The caller
// owns that snapshot; it must not pass mutable resolver or scratch state.
func NewAddressWriter(parent context.Context, send func([]byte, net.Addr) error) *Writer {
	w := &Writer{ctx: parent, requests: make(chan frameWrite), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			select {
			case <-parent.Done():
				return
			case r := <-w.requests:
				if parent.Err() != nil {
					r.done <- net.ErrClosed
					return
				}
				r.done <- send(r.frame, r.address)
			}
		}
	}()
	return w
}

// Send copies bytes before transfer; success means the underlying send returned
// success. Child cancellation releases both admission and completion waits.
func (w *Writer) Send(child context.Context, frame []byte) error {
	return w.SendTo(child, frame, nil)
}

func (w *Writer) SendTo(child context.Context, frame []byte, address net.Addr) error {
	if child.Err() != nil {
		return context.Cause(child)
	}
	if w.ctx.Err() != nil {
		return net.ErrClosed
	}
	r := frameWrite{frame: bytes.Clone(frame), address: address, done: make(chan error, 1)}
	select {
	case <-child.Done():
		return context.Cause(child)
	case <-w.ctx.Done():
		return net.ErrClosed
	case w.requests <- r:
	}
	select {
	case <-child.Done():
		return context.Cause(child)
	case <-w.ctx.Done():
		return net.ErrClosed
	case err := <-r.done:
		return err
	}
}

func (w *Writer) Wait() { <-w.done }
