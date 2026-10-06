package backend

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

type packetWrite struct {
	ctx   context.Context
	frame []byte
	done  chan packetWriteResult
}
type packetWriteResult struct {
	written int
	err     error
}

// packetWriter owns the shared framed stream. Admission commits no bytes;
// after admission send waits for the actual Write result, including joining
// its cancellation callback. An incomplete positive commit retires the parent.
type packetWriter struct {
	ctx      context.Context
	requests chan packetWrite
	done     chan struct{}
	retire   func()
}

func newPacketWriter(ctx context.Context, c net.Conn, cancel context.CancelFunc) *packetWriter {
	w := &packetWriter{ctx: ctx, requests: make(chan packetWrite), done: make(chan struct{})}
	var once sync.Once
	w.retire = func() { once.Do(func() { cancel(); _ = c.Close() }) }
	parentDone := make(chan struct{})
	stopParent := context.AfterFunc(ctx, func() { w.retire(); close(parentDone) })
	go func() {
		defer close(w.done)
		defer func() {
			if !stopParent() {
				<-parentDone
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-w.requests:
				result := w.write(c, r)
				r.done <- result
				if ctx.Err() != nil {
					return
				}
			}
		}
	}()
	return w
}
func (w *packetWriter) write(c net.Conn, r packetWrite) packetWriteResult {
	if w.ctx.Err() != nil {
		return packetWriteResult{err: net.ErrClosed}
	}
	if r.ctx.Err() != nil {
		return packetWriteResult{err: context.Cause(r.ctx)}
	}
	interrupted := make(chan error, 1)
	stop := context.AfterFunc(r.ctx, func() {
		err := c.SetWriteDeadline(time.Now())
		if err != nil {
			w.retire()
		}
		interrupted <- err
	})
	n, err := c.Write(r.frame)
	if err == nil && n != len(r.frame) {
		err = io.ErrShortWrite
	}
	if !stop() {
		// Join the callback before another request can touch the socket.
		interruptErr := <-interrupted
		if interruptErr == nil && (n == 0 || err == nil) && w.ctx.Err() == nil {
			if resetErr := c.SetWriteDeadline(time.Time{}); resetErr != nil {
				w.retire()
			}
		}
	}
	if err == nil {
		return packetWriteResult{written: n}
	}
	if n > 0 || r.ctx.Err() == nil || w.ctx.Err() != nil {
		w.retire()
	}
	if r.ctx.Err() != nil {
		err = context.Cause(r.ctx)
	}
	return packetWriteResult{written: n, err: err}
}

// frame is fresh encoded storage, independent of the WriteTo caller. Once
// handed off, only the worker completes this request; no asynchronous tail
// survives send returning an error.
func (w *packetWriter) send(ctx context.Context, frame []byte) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if w.ctx.Err() != nil {
		return net.ErrClosed
	}
	r := packetWrite{ctx: ctx, frame: frame, done: make(chan packetWriteResult, 1)}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-w.ctx.Done():
		return net.ErrClosed
	case w.requests <- r:
	}
	return (<-r.done).err
}
