package packetio

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func writeResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("write did not terminate")
		return nil
	}
}

func TestQueuePendingWriteCancellation(t *testing.T) {
	for _, mode := range []string{"close", "past", "future", "parent"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			q := New(parent, &net.UDPAddr{}, func(ctx context.Context, _ []byte, _ net.Addr) error {
				close(entered)
				<-ctx.Done()
				return context.Cause(ctx)
			})
			defer q.Close()
			result := make(chan error, 2)
			go func() { _, err := q.WriteTo([]byte("one"), &net.UDPAddr{}); result <- err }()
			<-entered
			// This writer also must leave the serialization wait on cancellation.
			go func() { _, err := q.WriteTo([]byte("two"), &net.UDPAddr{}); result <- err }()
			want := net.ErrClosed
			switch mode {
			case "close":
				_ = q.Close()
			case "parent":
				cancel()
			case "past":
				want = os.ErrDeadlineExceeded
				_ = q.SetWriteDeadline(time.Now().Add(-time.Second))
			case "future":
				want = os.ErrDeadlineExceeded
				_ = q.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
			}
			for range 2 {
				err := writeResult(t, result)
				if !errors.Is(err, want) {
					t.Fatalf("got %v, want %v", err, want)
				}
				if want == os.ErrDeadlineExceeded {
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Fatal("missing timeout semantics")
					}
				}
			}
		})
	}
}

func TestQueueWriteDeadlineResetAndClear(t *testing.T) {
	entered := make(chan context.Context, 2)
	release := make(chan struct{}, 2)
	q := New(context.Background(), &net.UDPAddr{}, func(ctx context.Context, _ []byte, _ net.Addr) error {
		entered <- ctx
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	})
	defer q.Close()
	result := make(chan error, 1)
	_ = q.SetWriteDeadline(time.Now().Add(time.Hour))
	go func() { _, err := q.WriteTo([]byte("one"), nil); result <- err }()
	ctx := <-entered
	q.mu.Lock()
	old := q.active.timer
	q.mu.Unlock()
	_ = q.SetWriteDeadline(time.Now().Add(2 * time.Hour))
	_ = q.SetWriteDeadline(time.Time{})
	q.mu.Lock()
	if !q.write.IsZero() {
		t.Error("clear failed")
	}
	q.mu.Unlock()
	if old.Stop() {
		t.Error("old deadline timer was not stopped")
	}
	if ctx.Err() != nil {
		t.Fatal("reset/clear canceled active write")
	}
	release <- struct{}{}
	if err := writeResult(t, result); err != nil {
		t.Fatal(err)
	}
	_ = q.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := q.WriteTo(nil, nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = q.SetWriteDeadline(time.Time{})
	go func() { _, err := q.WriteTo([]byte("two"), nil); result <- err }()
	<-entered
	release <- struct{}{}
	if err := writeResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestQueueConcurrentWriteCloseDeadline(t *testing.T) {
	for range 32 {
		entered := make(chan struct{})
		q := New(context.Background(), &net.UDPAddr{}, func(ctx context.Context, _ []byte, _ net.Addr) error {
			close(entered)
			<-ctx.Done()
			return context.Cause(ctx)
		})
		result := make(chan error, 1)
		go func() { _, err := q.WriteTo([]byte("one"), nil); result <- err }()
		<-entered
		var workers sync.WaitGroup
		for i := range 8 {
			workers.Go(func() {
				if i%2 == 0 {
					_ = q.Close()
				} else {
					_ = q.SetWriteDeadline(time.Now().Add(-time.Second))
					_ = q.SetWriteDeadline(time.Time{})
				}
			})
		}
		workers.Wait()
		err := writeResult(t, result)
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
		q.mu.Lock()
		if q.active != nil {
			t.Error("active operation retained after completion")
		}
		q.mu.Unlock()
	}
}

func TestQueueCompletedCommitWinsCancellation(t *testing.T) {
	var q *Queue
	q = New(context.Background(), &net.UDPAddr{}, func(context.Context, []byte, net.Addr) error {
		// Model cancellation after the transport confirms the complete frame.
		_ = q.SetWriteDeadline(time.Now().Add(-time.Second))
		return nil
	})
	defer q.Close()
	if n, err := q.WriteTo([]byte("committed"), nil); n != 9 || err != nil {
		t.Fatalf("complete commit reported failure: %d %v", n, err)
	}
}
