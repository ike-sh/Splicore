package application

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

type shutdownHandle struct {
	ports.RuntimeHandle
	err   error
	calls atomic.Int32
}

func (h *shutdownHandle) Close(context.Context) error {
	h.calls.Add(1)
	return h.err
}

func TestCloseRuntimePreservesAllShutdownErrors(t *testing.T) {
	first := errors.New("first listener close failure")
	second := errors.New("second listener close failure")
	handles := []*shutdownHandle{{err: first}, {err: second}, {}}
	s := &Service{runtime: &runtimeState{handles: map[identity.ID]ports.RuntimeHandle{
		"first": handles[0], "second": handles[1], "successful": handles[2],
	}}}
	err := s.CloseRuntime(context.Background())
	for _, want := range []error{first, second} {
		if !errors.Is(err, want) {
			t.Errorf("shutdown discarded %v: %v", want, err)
		}
	}
	for _, h := range handles {
		if h.calls.Load() != 1 {
			t.Error("shutdown did not close every handle exactly once")
		}
	}
	if !s.runtime.closed || len(s.runtime.handles) != 0 {
		t.Fatal("runtime ownership not released")
	}
	if err := s.CloseRuntime(context.Background()); err != nil {
		t.Fatal("repeated shutdown:", err)
	}
	for _, h := range handles {
		if h.calls.Load() != 1 {
			t.Error("repeated shutdown closed a released handle")
		}
	}
}

func TestCloseRuntimeConcurrentShutdown(t *testing.T) {
	h := &shutdownHandle{}
	s := &Service{runtime: &runtimeState{handles: map[identity.ID]ports.RuntimeHandle{"listener": h}}}
	var callers sync.WaitGroup
	for range 8 {
		callers.Go(func() {
			if err := s.CloseRuntime(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if h.calls.Load() != 1 || !s.runtime.closed || len(s.runtime.handles) != 0 {
		t.Fatal("concurrent shutdown did not release ownership exactly once")
	}
}
