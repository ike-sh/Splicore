package packet

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockedOwnerSocket struct {
	*capture
	entered, interrupted chan struct{}
	started, deadline    sync.Once
	active, late         atomic.Int64
}

func (p *blockedOwnerSocket) WriteTo([]byte, net.Addr) (int, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		p.late.Add(1)
	}
	p.active.Add(1)
	defer p.active.Add(-1)
	p.started.Do(func() { close(p.entered) })
	<-p.interrupted
	return 0, net.ErrClosed
}
func (p *blockedOwnerSocket) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		p.deadline.Do(func() { close(p.interrupted) })
	}
	return nil
}
func TestOwnedSocketJoinsWritesBeforeClose(t *testing.T) {
	raw := &blockedOwnerSocket{capture: &capture{}, entered: make(chan struct{}), interrupted: make(chan struct{})}
	p := Own(raw)
	written := make(chan error, 1)
	go func() { _, e := p.WriteTo([]byte{7}, peer); written <- e }()
	<-raw.entered
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("close blocked on write")
	}
	if e := <-written; !errors.Is(e, net.ErrClosed) {
		t.Fatal(e)
	}
	if raw.active.Load() != 0 {
		t.Fatal("active write at close return")
	}
	for range 32 {
		if _, e := p.WriteTo([]byte{9}, peer); !errors.Is(e, net.ErrClosed) {
			t.Fatal("late write", e)
		}
	}
	if raw.late.Load() != 0 {
		t.Fatal("underlying write after close")
	}
	if e := p.SetWriteDeadline(time.Time{}); !errors.Is(e, net.ErrClosed) {
		t.Fatal("cleared close deadline")
	}
	if e := p.SetDeadline(time.Time{}); !errors.Is(e, net.ErrClosed) {
		t.Fatal("cleared close deadline")
	}
	if e := p.Close(); e != nil {
		t.Fatal(e)
	}
}
