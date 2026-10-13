package xhttp

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Protocol admission is an explicit scope, never a reinterpretation of
// net.Conn.SetDeadline. Waiting for each delivery is owned by XHTTP; processing
// between deliveries consumes the caller's budget. Limits apply to both peers,
// independently of any proxy protocol's framing or authentication header size.
const admissionSteps = 1024
const admissionBytes = 64 << 10
const admissionLifetime = admissionSteps * associationTimeout

type admissionConn struct {
	net.Conn
	mu                  sync.Mutex
	readMu, writeMu     sync.Mutex
	remaining           time.Duration
	activeAt, until     time.Time
	waits, steps, bytes int
	err                 error
	done                bool
	clock, wall         *time.Timer
	chunk               int
}

func (c *logicalConn) BeginAdmission(budget time.Duration) (net.Conn, func() error) {
	if c.admissionStart != nil {
		c.admissionStart()
	}
	a := &admissionConn{Conn: c, remaining: budget, activeAt: time.Now(), until: time.Now().Add(admissionLifetime), chunk: max(1, c.admissionChunk)}
	a.clock = time.AfterFunc(admissionLifetime, a.expire)
	a.wall = time.AfterFunc(admissionLifetime, a.expire)
	a.clock.Reset(budget)
	return a, a.finish
}

func (a *admissionConn) expire() {
	a.mu.Lock()
	if !a.done {
		a.err = os.ErrDeadlineExceeded
		a.done = true
		a.clock.Stop()
		a.wall.Stop()
		a.Conn.Close()
	}
	a.mu.Unlock()
}

func (a *admissionConn) enter() (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.done {
		return false, a.err
	}
	if a.err != nil {
		return true, a.err
	}
	if a.waits == 0 {
		a.remaining -= time.Since(a.activeAt)
		a.clock.Stop()
	}
	a.steps++
	if a.remaining <= 0 || !time.Now().Before(a.until) || a.steps > admissionSteps {
		a.err = os.ErrDeadlineExceeded
		a.done = true
		a.clock.Stop()
		a.wall.Stop()
		a.Conn.Close()
		return true, a.err
	}
	a.waits++
	return true, nil
}

func (a *admissionConn) leave(n int, err error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bytes += n
	a.waits--
	if a.bytes > admissionBytes && err == nil {
		err = io.ErrShortBuffer
	}
	if err != nil && a.err == nil {
		a.err = err
	}
	if a.err != nil {
		a.done = true
		a.clock.Stop()
		a.wall.Stop()
		a.Conn.Close()
	}
	if a.waits == 0 && !a.done && a.err == nil {
		a.activeAt = time.Now()
		a.clock.Reset(a.remaining)
	}
	return a.err
}

func (a *admissionConn) Read(b []byte) (int, error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	scoped, err := a.enter()
	if err != nil {
		return 0, err
	}
	if !scoped {
		return a.Conn.Read(b)
	}
	_ = a.Conn.SetReadDeadline(time.Now().Add(associationTimeout))
	n, err := a.Conn.Read(b[:min(len(b), admissionBytes+1)])
	return n, a.leave(n, err)
}

func (a *admissionConn) Write(b []byte) (int, error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	n := 0
	for n < len(b) {
		scoped, err := a.enter()
		if err != nil {
			return n, err
		}
		if !scoped {
			v, err := a.Conn.Write(b[n:])
			return n + v, err
		}
		// A pipe Write can span many POSTs without returning. Split at the
		// minimum configured packet size so every bounded wait makes progress.
		_ = a.Conn.SetWriteDeadline(time.Now().Add(associationTimeout))
		v, err := a.Conn.Write(b[n:min(len(b), n+a.chunk)])
		n += v
		if err = a.leave(v, err); err != nil {
			return n, err
		}
		if v == 0 {
			return n, io.ErrNoProgress
		}
	}
	return n, nil
}

func (a *admissionConn) finish() error {
	a.readMu.Lock()
	defer a.readMu.Unlock()
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.done {
		return a.err
	}
	a.remaining -= time.Since(a.activeAt)
	if a.remaining <= 0 && a.err == nil {
		a.err = os.ErrDeadlineExceeded
	}
	a.done = true
	a.clock.Stop()
	a.wall.Stop()
	if a.err != nil {
		a.Conn.Close()
		return a.err
	}
	return a.Conn.SetDeadline(time.Time{})
}

func (a *admissionConn) Close() error {
	a.mu.Lock()
	a.done = true
	if a.err == nil {
		a.err = net.ErrClosed
	}
	a.clock.Stop()
	a.wall.Stop()
	a.mu.Unlock()
	return a.Conn.Close()
}
