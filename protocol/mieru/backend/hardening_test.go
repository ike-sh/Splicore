package backend

import (
	"context"
	"sync"
	"testing"
)

func TestPhase15StoppedHandleRejectsStaleActivation(t *testing.T) {
	done := make(chan struct{})
	close(done)
	h := &mieruHandle{closed: true, done: done, total: &meter{}}
	barrier := make(chan struct{})
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			<-barrier
			h.Activate()
			if err := h.Start(context.Background()); err == nil {
				t.Error("closed handle restarted")
			}
			if err := h.Close(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	close(barrier)
	workers.Wait()
	if h.admitted.Load() {
		t.Error("stale callback reopened admission")
	}
}
