package clientruntime

import (
	"context"
	"sync"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

func hardeningCandidate(t *testing.T, m *Manager) *Prepared {
	t.Helper()
	factories, err := registry.NewOutbounds()
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.Prepare(context.Background(), client.Empty(), nil, factories)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPhase15CandidateCannotActivateAfterClose(t *testing.T) {
	m := New()
	p := hardeningCandidate(t, m)
	defer p.Abort()
	defer m.Close(context.Background())
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Activate(); err == nil {
		t.Error("candidate resurrected closed manager")
	}
	if m.current.Load() != nil {
		t.Error("stopped manager published a generation")
	}
	if len(m.underlay.Status().Generations) != 0 {
		t.Error("candidate lease not released")
	}
}

func TestPhase15StaleCandidateCannotReplaceCurrent(t *testing.T) {
	m := New()
	defer m.Close(context.Background())
	old := hardeningCandidate(t, m)
	defer old.Abort()
	winner := hardeningCandidate(t, m)
	defer winner.Abort()
	if err := winner.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := old.Activate(); err == nil {
		t.Error("stale candidate replaced current generation")
	}
	if m.current.Load() != winner.s {
		t.Error("winning generation lost ownership")
	}
}

func TestPhase15CandidateConsumptionConcurrent(t *testing.T) {
	m := New()
	defer m.Close(context.Background())
	p := hardeningCandidate(t, m)
	barrier := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(abort bool) {
			defer workers.Done()
			<-barrier
			if abort {
				_ = p.Abort()
			} else {
				_ = p.Activate()
			}
		}(i%2 == 0)
	}
	close(barrier)
	workers.Wait()
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(m.underlay.Status().Generations) != 0 {
		t.Error("consumption leaked lease")
	}
}
