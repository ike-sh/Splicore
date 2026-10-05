//go:build !with_gvisor

package nativetun

import (
	"context"
	"errors"
	"testing"
)

func TestUnavailableBackendStartCleanup(t *testing.T) {
	device := newTestDevice()
	r, err := New(context.Background(), device, Options{MTU: 1500, Dispatcher: testDispatcher{}})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.Start(), ErrUnavailable) {
		t.Fatal("missing backend was accepted")
	}
	if !errors.Is(r.Close(), ErrUnavailable) || r.State() != Failed {
		t.Fatal("failure result lost")
	}
	select {
	case <-device.interrupted:
		t.Fatal("failed backend interrupted a device it never borrowed")
	default:
	}
	if device.closes.Load() != 0 {
		t.Fatal("released unborrowed host device")
	}
}
