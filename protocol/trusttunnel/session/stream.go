package session

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type streamAddr string

func (a streamAddr) Network() string { return "trusttunnel" }
func (a streamAddr) String() string  { return string(a) }

type writeResult struct {
	n   int
	err error
}
type writeRequest struct {
	data       []byte
	result     chan writeResult
	closeWrite bool
}

type readResult struct {
	data []byte
	err  error
}

// This independently owned adapter follows the existing Naive bounded stream
// design, kept private to avoid coupling protocol lifetimes or padding.
// bodyConn gives CONNECT bodies real stream deadlines without changing a shared
// HTTP connection's deadlines. The pump, queue and reader hold at most three
// 32KiB buffers in total.
// A write timeout cancels this stream; its partially written request cannot be
// reused. Read deadlines can be cleared without dropping received bytes.
type bodyConn struct {
	r                    io.ReadCloser
	w                    io.Writer
	closeWrite           func() error
	prepareCloseWrite    func() error
	stop                 func(bool)
	local, remote        net.Addr
	done                 chan struct{}
	reads                chan readResult
	pumpDone             chan struct{}
	writes               chan writeRequest
	writerDone           chan struct{}
	once                 sync.Once
	rmu, wmu, mu         sync.Mutex
	pending              []byte
	pendingErr           error
	rDeadline, wDeadline time.Time
	rChanged, wChanged   chan struct{}
	idle                 time.Duration
	last                 time.Time
	idleTimer            *time.Timer
	closed               bool
	wroteEOF             atomic.Bool
}

func newBodyConn(r io.ReadCloser, w io.Writer, closeWrite func() error, stop func(bool), local, remote net.Addr, idle time.Duration) *bodyConn {
	c := &bodyConn{r: r, w: w, closeWrite: closeWrite, stop: stop, local: local, remote: remote,
		done: make(chan struct{}), reads: make(chan readResult, 1), pumpDone: make(chan struct{}), writes: make(chan writeRequest), writerDone: make(chan struct{}),
		rChanged: make(chan struct{}), wChanged: make(chan struct{}), last: time.Now()}
	c.setIdle(idle)
	go c.readPump()
	go c.writePump()
	return c
}
func (c *bodyConn) readPump() {
	defer close(c.pumpDone)
	for {
		buffer := make([]byte, 32<<10)
		n, err := c.r.Read(buffer)
		for n == 0 && err == nil {
			// A legal empty HTTP/3 DATA frame can produce (0, nil). Keep
			// reading without dropping the stream or allocating another buffer.
			// A cancelable pause also bounds CPU use for a broken empty reader.
			pause := time.NewTimer(time.Millisecond)
			select {
			case <-pause.C:
			case <-c.done:
				pause.Stop()
				return
			}
			n, err = c.r.Read(buffer)
		}
		select {
		case c.reads <- readResult{buffer[:n], err}:
		case <-c.done:
			return
		}
		if err != nil {
			return
		}
	}
}
func waitDeadline(t time.Time) (<-chan time.Time, func()) {
	if t.IsZero() {
		return nil, func() {}
	}
	timer := time.NewTimer(time.Until(t))
	return timer.C, func() { timer.Stop() }
}
func (c *bodyConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		deadline, changed, closed := c.rDeadline, c.rChanged, c.closed
		c.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			c.touch()
			return n, nil
		}
		if c.pendingErr != nil {
			return 0, c.pendingErr
		}
		expiry, stop := waitDeadline(deadline)
		select {
		case result := <-c.reads:
			c.pending = result.data
			c.pendingErr = result.err
		case <-expiry:
			stop()
			return 0, os.ErrDeadlineExceeded
		case <-changed:
		case <-c.done:
			stop()
			return 0, net.ErrClosed
		}
		stop()
	}
}
func (c *bodyConn) writePump() {
	defer close(c.writerDone)
	for {
		select {
		case req := <-c.writes:
			var n int
			var e error
			if req.closeWrite {
				if c.prepareCloseWrite != nil {
					e = c.prepareCloseWrite()
				}
				if e == nil {
					// Full Close must preserve delivery once graceful FIN is
					// requested, including the interval before Close returns.
					c.wroteEOF.Store(true)
					e = c.closeWrite()
					if e != nil {
						c.wroteEOF.Store(false)
					}
				}
			} else {
				n, e = c.w.Write(req.data)
			}
			req.result <- writeResult{n, e}
		case <-c.done:
			return
		}
	}
}
func (c *bodyConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	return c.writeLocked(p, false)
}

// writeLocked applies the same bounded worker, deadline and cancellation rules
// to data writes and send-half completion. The caller holds wmu.
func (c *bodyConn) writeLocked(p []byte, closeWrite bool) (int, error) {
	result := make(chan writeResult, 1)
	request := writeRequest{data: p, result: result, closeWrite: closeWrite}
	sent := false
	for {
		c.mu.Lock()
		deadline, changed, closed := c.wDeadline, c.wChanged, c.closed
		c.mu.Unlock()
		if closed {
			if sent {
				v := <-result
				return v.n, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			if sent {
				c.terminate()
				v := <-result
				return v.n, os.ErrDeadlineExceeded
			}
			return 0, os.ErrDeadlineExceeded
		}
		expiry, stop := waitDeadline(deadline)
		var out chan writeRequest
		if !sent {
			out = c.writes
		}
		select {
		case out <- request:
			sent = true
		case v := <-result:
			stop()
			if v.n > 0 {
				c.touch()
			}
			return v.n, v.err
		case <-expiry:
			stop()
			if sent {
				c.terminate()
				v := <-result
				return v.n, os.ErrDeadlineExceeded
			}
			return 0, os.ErrDeadlineExceeded
		case <-changed:
		case <-c.done:
			stop()
			if sent {
				v := <-result
				return v.n, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		stop()
	}
}
func (c *bodyConn) touch() { c.mu.Lock(); defer c.mu.Unlock(); c.last = time.Now(); c.armIdleLocked() }
func (c *bodyConn) setIdle(t time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.idle = t
	c.armIdleLocked()
}
func (c *bodyConn) armIdleLocked() {
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	if c.closed || c.idle <= 0 {
		return
	}
	delay := time.Until(c.last.Add(c.idle))
	c.idleTimer = time.AfterFunc(max(0, delay), func() {
		c.mu.Lock()
		expired := !c.closed && time.Since(c.last) >= c.idle
		c.mu.Unlock()
		if expired {
			c.terminate()
		}
	})
}
func (c *bodyConn) terminate() {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.idleTimer != nil {
			c.idleTimer.Stop()
		}
		close(c.done)
		c.mu.Unlock()
		if c.stop != nil {
			c.stop(c.wroteEOF.Load())
		}
		_ = c.closeWrite()
		_ = c.r.Close()
	})
}
func (c *bodyConn) Close() error { c.terminate(); <-c.pumpDone; <-c.writerDone; return nil }
func (c *bodyConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wroteEOF.Load() {
		return nil
	}
	_, err := c.writeLocked(nil, true)
	return err
}
func (c *bodyConn) LocalAddr() net.Addr  { return c.local }
func (c *bodyConn) RemoteAddr() net.Addr { return c.remote }
func (c *bodyConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.rDeadline = t
	close(c.rChanged)
	c.rChanged = make(chan struct{})
	return nil
}
func (c *bodyConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.wDeadline = t
	close(c.wChanged)
	c.wChanged = make(chan struct{})
	return nil
}
func (c *bodyConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// untilEstablished watches the caller during CONNECT only. Successful streams
// remain owned by the returned connection after the caller's dial scope ends.
func untilEstablished(ctx context.Context, cancel context.CancelFunc) func() {
	stop := context.AfterFunc(ctx, cancel)
	return func() { stop() }
}
