package packetio

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestWriterChildOwnershipAndSibling(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan []byte), make(chan struct{})
	w := NewWriter(parent, func(b []byte) error {
		entered <- b
		select {
		case <-release:
			return nil
		case <-parent.Done():
			return net.ErrClosed
		}
	})
	defer w.Wait()
	defer cancel()
	child, closeChild := context.WithCancel(parent)
	defer closeChild()
	frame := []byte("owned-frame")
	result := make(chan error, 1)
	go func() { result <- w.Send(child, frame) }()
	owned := <-entered
	closeChild()
	if err := writeResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	copy(frame, "new-scratch")
	if !bytes.Equal(owned, []byte("owned-frame")) {
		t.Fatal("retained caller storage")
	}
	// A dead request awaiting handoff must disappear without reaching send.
	dead, closeDead := context.WithCancel(parent)
	go func() { result <- w.Send(dead, []byte("dead")) }()
	closeDead()
	if err := writeResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	go func() { result <- w.Send(parent, []byte("sibling")) }()
	release <- struct{}{}
	if got := <-entered; string(got) != "sibling" {
		t.Fatalf("dead request executed: %q", got)
	}
	release <- struct{}{}
	if err := writeResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestWriterQueueLifecycle(t *testing.T) {
	for _, mode := range []string{"close", "future", "past", "parent", "clear"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			entered, release := make(chan struct{}), make(chan struct{})
			w := NewWriter(parent, func([]byte) error {
				close(entered)
				select {
				case <-release:
					return nil
				case <-parent.Done():
					return net.ErrClosed
				}
			})
			defer w.Wait()
			defer cancel()
			q := New(parent, nil, func(ctx context.Context, b []byte, _ net.Addr) error { return w.Send(ctx, b) })
			defer q.Close()
			result := make(chan error, 2)
			go func() { _, err := q.WriteTo([]byte("frame"), nil); result <- err }()
			<-entered
			want := net.ErrClosed
			if mode != "clear" {
				go func() { _, err := q.WriteTo([]byte("uncommitted"), nil); result <- err }()
			}
			switch mode {
			case "close":
				q.Close()
			case "parent":
				cancel()
			case "future":
				want = os.ErrDeadlineExceeded
				q.SetWriteDeadline(time.Now().Add(time.Millisecond))
			case "past":
				want = os.ErrDeadlineExceeded
				q.SetWriteDeadline(time.Now().Add(-time.Second))
			case "clear":
				q.SetWriteDeadline(time.Now().Add(time.Hour))
				q.SetWriteDeadline(time.Now().Add(time.Minute))
				q.SetWriteDeadline(time.Now().Add(2 * time.Hour))
				q.SetWriteDeadline(time.Time{})
				close(release)
				if err := writeResult(t, result); err != nil {
					t.Fatal(err)
				}
				return
			}
			for range 2 {
				if err := writeResult(t, result); !errors.Is(err, want) {
					t.Fatalf("%v want %v", err, want)
				}
			}
			q.mu.Lock()
			retained := q.active != nil
			q.mu.Unlock()
			if retained {
				t.Fatal("retained completed child operation")
			}
			q.Close()
			cancel()
			w.Wait()
			t.Log("Before: pending=0 queued=0 workers=1 associations=1; Blocked: pending=2 parentExecuting=1 buffered=0; AfterChildCancel: pending=0 buffered=0; AfterParentClose: workers=0 associations=0 (all caller results received, worker joined)")
		})
	}
}

func TestWriterParentChildDeadlineRace1000(t *testing.T) {
	for range 1000 {
		parent, cancel := context.WithCancel(context.Background())
		entered := make(chan struct{})
		w := NewWriter(parent, func([]byte) error { close(entered); <-parent.Done(); return net.ErrClosed })
		q := New(parent, nil, func(ctx context.Context, b []byte, _ net.Addr) error { return w.Send(ctx, b) })
		result := make(chan error, 1)
		go func() { _, err := q.WriteTo([]byte("frame"), nil); result <- err }()
		<-entered
		var group sync.WaitGroup
		group.Go(func() { q.Close() })
		group.Go(cancel)
		group.Go(func() { q.SetWriteDeadline(time.Now().Add(-time.Second)); q.SetWriteDeadline(time.Time{}) })
		group.Wait()
		if err := writeResult(t, result); !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
		w.Wait()
	}
}
