package session

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type emptyBodyReader struct{ reads atomic.Int64 }

func (r *emptyBodyReader) Read([]byte) (int, error) { r.reads.Add(1); return 0, nil }
func (*emptyBodyReader) Close() error               { return nil }

func TestStreamEmptyReadsDeadlineAndClose(t *testing.T) {
	r := &emptyBodyReader{}
	c := newBodyConn(r, io.Discard, func() error { return nil }, nil, streamAddr("local"), streamAddr("remote"), 0)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("logical deadline lost: %v", err)
	}
	// An always empty reader must neither fail on a single empty read nor spin
	// indefinitely at full CPU. Allow ample scheduler variation under -race.
	if n := r.reads.Load(); n > 1000 {
		t.Fatalf("unbounded empty-read spin: %d", n)
	}
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close failed to join empty reader")
	}
	if _, err = c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

// Completion may now write a final H3 DATA frame. Flow control on that write
// must respect updated logical deadlines and must not prevent full Close.
func TestStreamCloseWriteDeadlineAndClose(t *testing.T) {
	for _, action := range []string{"deadline", "full-close"} {
		t.Run(action, func(t *testing.T) {
			r, w := io.Pipe()
			defer w.Close()
			entered, stopped := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var graceful atomic.Bool
			c := newBodyConn(r, io.Discard, func() error { return nil }, func(fin bool) {
				graceful.Store(fin)
				once.Do(func() { close(stopped) })
			}, streamAddr("local"), streamAddr("remote"), 0)
			defer c.Close()
			c.prepareCloseWrite = func() error { close(entered); <-stopped; return net.ErrClosed }
			result := make(chan error, 1)
			go func() { result <- c.CloseWrite() }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("completion write did not start")
			}
			closed := make(chan struct{})
			if action == "deadline" {
				_ = c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
			} else {
				go func() { _ = c.Close(); close(closed) }()
			}
			select {
			case err := <-result:
				want := error(net.ErrClosed)
				if action == "deadline" {
					want = os.ErrDeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatalf("CloseWrite error=%v want=%v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("blocked completion did not cancel")
			}
			if graceful.Load() {
				t.Fatal("unfinished preparation was treated as graceful FIN")
			}
			if action == "full-close" {
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("Close did not join both pumps")
				}
			}
		})
	}
}
