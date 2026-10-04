package networkruntime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
)

func TestPhase15SystemBootstrapCannotOutliveEngine(t *testing.T) {
	e, err := New(P.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if _, err = e.Bootstrap(context.Background(), "localhost"); err == nil {
		t.Fatal("closed engine still resolves system DNS")
	}
}

func TestPhase15DelayedHealthCompletionCannotPolluteReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(204)
	}))
	defer func() { cancel(); close(release); target.Close() }()
	member := P.Action{Kind: P.Direct}
	id := testID(1)
	c := P.Config{Groups: []P.PolicyGroup{{ID: id, Name: "owned", Type: "fallback", Members: []P.Action{member}, Fallback: &P.FallbackSettings{Probe: probeSpec(target.URL)}}}}
	old, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	done := make(chan struct{})
	go func() { old.probe(ctx, id, member); close(done) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("probe did not reach barrier")
	}
	next, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	next.Inherit(old)
	release <- struct{}{}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("probe not joined")
	}
	if old.memberHealth(old.groups[id], member).State != "healthy" || next.memberHealth(next.groups[id], member).State != "unknown" {
		t.Fatal("delayed health crossed snapshot ownership")
	}
}
