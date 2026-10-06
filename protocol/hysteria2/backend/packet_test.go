package backend

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestPacketPendingReadDeadlineAndClose(t *testing.T) {
	for _, operation := range []string{"deadline", "close"} {
		t.Run(operation, func(t *testing.T) {
			p := newPacket(context.Background(), &net.UDPAddr{}, 1, func(context.Context, []byte) error { return nil })
			defer p.Close()
			done := make(chan error, 1)
			go func() { _, _, err := p.ReadFrom(make([]byte, 4096)); done <- err }()
			if operation == "deadline" {
				_ = p.SetReadDeadline(time.Now().Add(-time.Second))
			} else {
				_ = p.Close()
			}
			select {
			case err := <-done:
				if operation == "deadline" && !errors.Is(err, os.ErrDeadlineExceeded) || operation == "close" && !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("pending read did not observe state change")
			}
		})
	}
}
func TestPacketConcurrentDeadlineAndShutdown(t *testing.T) {
	p := newPacket(context.Background(), &net.UDPAddr{}, 1, func(context.Context, []byte) error { return nil })
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				_ = p.SetDeadline(time.Now().Add(time.Hour))
			}
		})
	}
	wg.Go(func() { _ = p.Close() })
	wg.Wait()
	if _, _, err := p.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
