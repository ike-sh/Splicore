//go:build with_quic && with_utls

package native

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPhase32PaddingAdmissionDeadlineOwnership(t *testing.T) {
	for cycle := range 24 {
		a, b := net.Pipe()
		a.SetReadDeadline(time.Now().Add(time.Millisecond))
		c, finish := vlessAdmission(context.Background(), a, 35*time.Second)
		started := time.Now()
		_, err := c.Read(make([]byte, 1))
		if err == nil || time.Since(started) > time.Second {
			t.Fatalf("cycle %d: tighter transport deadline overwritten", cycle)
		}
		if err = finish(); err != nil {
			t.Fatal(err)
		}
		a.Close()
		b.Close()
	}
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	c, finish := vlessAdmission(ctx, a, 35*time.Second)
	defer finish()
	cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("shutdown did not close admission")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown leaked admission")
	}
}
