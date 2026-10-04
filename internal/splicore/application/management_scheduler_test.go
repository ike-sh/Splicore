package application

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/engine/native"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/secretvault"
	"github.com/sagernet/sing-box/internal/splicore/storage/sqlite"
	"github.com/sagernet/sing-box/internal/splicore/version"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPhase14SchedulerBoundedCancellationAndClock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	vault, _ := secretvault.New("fixture", make([]byte, 32))
	store, e := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state", "state.db"), sqlite.Options{Cipher: vault})
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	p, r, x, e := registry.Foundation()
	if e != nil {
		t.Fatal(e)
	}
	s, e := New(store, p, r, x, version.Current())
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableRuntime(ctx); e != nil {
		t.Fatal(e)
	}
	defer s.CloseRuntime(context.Background())
	factories, e := registry.NewOutbounds(native.SnellOutboundFactory{})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableClientRuntime(ctx, factories); e != nil {
		t.Fatal(e)
	}
	entered := make(chan struct{}, 8)
	var active, peak atomic.Int64
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		for previous := peak.Load(); n > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, n) {
				break
			}
		}
		defer active.Add(-1)
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer fixture.Close()
	for i := 0; i < 8; i++ {
		plan, e := s.PreviewManagement(ctx, ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "scheduled", Kind: "ruleset", Format: "canonical-rules", RefreshEnabled: true, IntervalSeconds: 60, AllowPrivate: true}, Source: &provider.Source{URL: fixture.URL}})
		if e != nil || !plan.Applicable {
			t.Fatal(e, plan.Reason)
		}
		if _, e = s.ApplyManagement(ctx, ManagementApply{plan.Token, plan.Revision}); e != nil {
			t.Fatal(e)
		}
	}
	ticks := make(chan time.Time)
	done := make(chan struct{})
	scheduled, stop := context.WithCancel(ctx)
	go s.runManagementScheduler(scheduled, done, ticks)
	now := time.Now()
	ticks <- now
	ticks <- now.Add(2 * time.Hour)
	for range 4 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("scheduler did not dispatch bounded workers")
		}
	}
	if peak.Load() > 4 {
		t.Fatal("unbounded HTTP concurrency")
	}
	stop()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("scheduler workers did not cancel")
	}
	diag, e := s.ProviderDiagnostics(ctx)
	if e != nil || diag.ActiveRefreshes != 0 {
		t.Fatal("scheduler retained refresh ownership", e)
	}
	// Backoff never shortens the configured cadence; monotonic ticks schedule it.
	slow := provider.Provider{ID: "00000000-0000-4000-8000-000000000000", IntervalSeconds: 86400 * 30, Failures: 10}
	if scheduleDelay(slow) < 30*24*time.Hour {
		t.Fatal("backoff shortened configured interval")
	}
	status, e := s.ClientStatus(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range status.State.Management.Providers {
		if p.Generation != 0 {
			t.Fatal("canceled refresh published generation")
		}
	}
}
