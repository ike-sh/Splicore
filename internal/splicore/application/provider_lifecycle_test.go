package application

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/clientruntime"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

// Only the read side is reached: every owned HTTP request is canceled before
// parsing/commit. SQL permission fixtures are unnecessary for this lifecycle.
type providerRefreshMemory struct {
	ports.ClientRepository
	mu    sync.Mutex
	state client.ProfileState
	url   string
}

func (r *providerRefreshMemory) ClientState(ctx context.Context) (client.ProfileState, error) {
	if e := ctx.Err(); e != nil {
		return client.ProfileState{}, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state.Clone(), nil
}
func (r *providerRefreshMemory) RevealProviderSource(ctx context.Context, id identity.ID) (provider.Source, error) {
	if e := ctx.Err(); e != nil {
		return provider.Source{}, e
	}
	return provider.Source{URL: r.url + "/" + string(id)}, nil
}

type providerRefreshBackend struct {
	calls atomic.Int64
	bad   atomic.Bool
}

func (*providerRefreshBackend) Capabilities() underlay.Capabilities {
	return underlay.Capabilities{PerSocket: true, SystemResolver: true}
}
func (b *providerRefreshBackend) Protect(_ context.Context, s underlay.Scope, _, _ string, _ syscall.RawConn) error {
	b.calls.Add(1)
	if s.Purpose != underlay.ProviderFetch || s.Generation == "" {
		b.bad.Store(true)
	}
	return nil
}
func (*providerRefreshBackend) Reconcile(context.Context, []underlay.Endpoint) error { return nil }
func (*providerRefreshBackend) Verify(ctx context.Context) error                     { return ctx.Err() }

func TestProviderRefreshSchedulerReloadAndShutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	entered, exited := make(chan struct{}, 16), make(chan struct{}, 16)
	var active, peak atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-r.Context().Done()
		active.Add(-1)
		exited <- struct{}{}
	}))
	defer func() { cancel(); server.Close() }()
	state := client.Empty()
	for i := 0; i < 8; i++ {
		id, e := identity.NewID()
		if e != nil {
			t.Fatal(e)
		}
		p := provider.Provider{ID: id, Name: fmt.Sprintf("synthetic-provider-%d", i), Kind: "proxy", Format: "canonical", RefreshEnabled: true, IntervalSeconds: 60, AllowPrivate: true}
		p.Defaults()
		state.Management.Providers = append(state.Management.Providers, p)
	}
	backend := &providerRefreshBackend{}
	f := underlay.NewWithBackend(backend)
	external, e := f.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	manager := clientruntime.NewWithUnderlay(f)
	factories, e := registry.NewOutbounds()
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := manager.Prepare(ctx, state, nil, factories)
	if e != nil {
		t.Fatal(e)
	}
	prepared.Activate()
	repo := &providerRefreshMemory{state: state, url: server.URL}
	s := &Service{client: &clientState{repo: repo, manager: manager, factories: factories, management: newManagementState()}}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if e := s.StopManagement(cleanup); e != nil {
			t.Error(e)
		}
		if e := manager.Close(cleanup); e != nil {
			t.Error(e)
		}
		if e := external.Close(); e != nil {
			t.Error(e)
		}
		if f.Status().ActiveLeases != 0 {
			t.Error("provider/generation lease leaked", f.Status())
		}
	})
	// Real timer construction, repeated Start and timer/worker Stop are joined.
	if e = s.StartManagement(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.StartManagement(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.StopManagementScheduler(ctx); e != nil {
		t.Fatal(e)
	}
	if backend.calls.Load() != 0 {
		t.Fatal("startup fetched without due tick")
	}
	wait := func(ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatal(what, ctx.Err())
		}
	}
	for round := 0; round < 2; round++ {
		ticks := make(chan time.Time)
		done := make(chan struct{})
		scheduled, stop := context.WithCancel(ctx)
		m := s.client.management
		m.mu.Lock()
		m.scheduleCancel = stop
		m.scheduleDone = done
		m.mu.Unlock()
		go s.runManagementScheduler(scheduled, done, ticks)
		now := time.Now()
		select {
		case ticks <- now:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		select {
		case ticks <- now.Add(2 * time.Hour):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		for range 4 {
			wait(entered, "scheduled request not entered")
		}
		if peak.Load() > 4 {
			t.Fatal("unbounded refresh workers", peak.Load())
		}
		if round == 0 {
			// Reload while the old fetches still own sockets and generation references.
			state.Revision++
			next, e := manager.Prepare(ctx, state, nil, factories)
			if e != nil {
				t.Fatal(e)
			}
			next.Activate()
			repo.mu.Lock()
			repo.state = state
			repo.mu.Unlock()
			if f.Status().ActiveLeases < 3 {
				t.Fatal("reload prematurely retired active fetch generation", f.Status())
			}
		}
		if e = s.StopManagementScheduler(ctx); e != nil {
			t.Fatal(e)
		}
		for range 4 {
			wait(exited, "server worker not canceled")
		}
		diagnostic, e := s.ProviderDiagnostics(ctx)
		if e != nil || diagnostic.ActiveRefreshes != 0 || diagnostic.Scheduler {
			t.Fatal("refresh ownership/timer retained", diagnostic, e)
		}
		if leases := f.Status().ActiveLeases; leases != 2 {
			t.Fatal("fetch/old generation lease leaked", leases)
		}
	}
	if backend.bad.Load() || backend.calls.Load() != 8 {
		t.Fatal("refresh lost protected dialer", backend.calls.Load(), backend.bad.Load())
	}
	if e = s.StopManagement(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = s.PreviewProviderRefresh(ctx, state.Management.Providers[0].ID); e == nil {
		t.Fatal("stopped provider admitted work")
	}
	t.Logf("periodic/reloaded fetches=%d peak=%d protected calls=%d; workers, timers, old generation and sockets joined", backend.calls.Load(), peak.Load(), backend.calls.Load())
}
