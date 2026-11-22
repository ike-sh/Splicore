package session

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUntilEstablishedJoinsCancellationOwner(t *testing.T) {
	ctx, cancelContext := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	finish := untilEstablished(ctx, func() {
		close(entered)
		<-release
	})
	cancelContext()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("cancellation callback did not start")
	}
	finished := make(chan bool, 1)
	go func() {
		finished <- finish()
	}()
	select {
	case <-finished:
		t.Fatal("establishment returned before cancellation owner completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case established := <-finished:
		if established {
			t.Fatal("canceled stream ownership transferred to the caller")
		}
	case <-time.After(time.Second):
		t.Fatal("establishment did not join cancellation owner")
	}
	if finish() {
		t.Fatal("repeated completion changed canceled ownership")
	}
}

func TestUntilEstablishedTransfersOwnership(t *testing.T) {
	ctx, cancelContext := context.WithCancel(context.Background())
	defer cancelContext()
	canceled := make(chan struct{}, 1)
	finish := untilEstablished(ctx, func() { canceled <- struct{}{} })
	if !finish() {
		t.Fatal("live stream ownership was not transferred")
	}
	if !finish() {
		t.Fatal("repeated completion changed established ownership")
	}
	cancelContext()
	select {
	case <-canceled:
		t.Fatal("caller cancellation reached an established stream")
	case <-time.After(30 * time.Millisecond):
	}
}

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
