package sqlite

import (
	"context"
	"sync"
	"testing"
)

func TestPhase15ConcurrentCloseJoinsInstallationRelease(t *testing.T) {
	s, path := newStore(t)
	barrier := make(chan struct{})
	results := make(chan error, 16)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); <-barrier; results <- s.Close() }()
	}
	close(barrier)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Error("duplicate release", err)
		}
	}
	next, err := Open(context.Background(), path, options(t))
	if err != nil {
		t.Fatal("installation lock was not released", err)
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
}
