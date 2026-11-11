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

func TestQueueBufferOwnershipAndCloseDeadline(t *testing.T) {
	q := New(context.Background(), &net.UDPAddr{}, func(context.Context, []byte, net.Addr) error { return nil })
	defer q.Close()
	b := []byte("owned")
	q.Deliver(b, &net.UDPAddr{})
	clear(b)
	got := make([]byte, 16)
	n, _, err := q.ReadFrom(got)
	if err != nil || string(got[:n]) != "owned" {
		t.Fatal("queue retained producer scratch")
	}
	result := make(chan error, 1)
	go func() { _, _, err := q.ReadFrom(got); result <- err }()
	_ = q.SetReadDeadline(time.Now().Add(-time.Second))
	if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = q.SetReadDeadline(time.Time{})
	go func() { _, _, err := q.ReadFrom(got); result <- err }()
	_ = q.Close()
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
func TestQueueConcurrentDirectionsAndShutdown(t *testing.T) {
	for range 64 {
		q := New(context.Background(), &net.UDPAddr{}, func(context.Context, []byte, net.Addr) error { return nil })
		barrier := make(chan struct{})
		var wg sync.WaitGroup
		for i := range 6 {
			wg.Go(func() {
				<-barrier
				switch i {
				case 0:
					_, _, _ = q.ReadFrom(make([]byte, 16))
				case 1:
					_, _ = q.WriteTo([]byte("synthetic"), &net.UDPAddr{})
				case 2:
					q.Deliver([]byte("synthetic"), &net.UDPAddr{})
				case 3:
					_ = q.SetDeadline(time.Now().Add(time.Second))
				default:
					_ = q.Close()
				}
			})
		}
		close(barrier)
		wg.Wait()
		_ = q.Close()
	}
}
