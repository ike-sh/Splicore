package application

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func service(t *testing.T) *Service {
	t.Helper()
	s, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "private", "state.db"), sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	p, e, x, err := registry.Foundation()
	if err != nil {
		t.Fatal(err)
	}
	app, err := New(s, p, e, x, version.Current())
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func TestApplicationGenerationAndPagination(t *testing.T) {
	s := service(t)
	ctx := context.Background()
	system, err := s.System(ctx)
	if err != nil || system.Health != "degraded" || system.Foundation.Engines != 1 {
		t.Fatal("foundation health inaccurate")
	}
	page, err := s.Capabilities(ctx, "", 1)
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatal("first page", err)
	}
	next, err := s.Capabilities(ctx, page.NextCursor, 200)
	if err != nil || len(next.Items) != 3 || next.NextCursor != "" {
		t.Fatal("next page", err)
	}
	request, _ := identity.NewID()
	actor := identity.Actor{Principal: "test-operator", RequestID: request}
	a, op, err := s.CreateAccount(ctx, "Alice", 0, actor)
	if err != nil || op.State != identity.Committed {
		t.Fatal(err)
	}
	if _, err = s.Capabilities(ctx, page.NextCursor, 1); err == nil {
		t.Fatal("cursor survived generation change")
	}
	a.Name = "Alice updated"
	if _, err = s.UpdateAccount(ctx, a, 1, 1, actor); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdateAccount(ctx, a, 1, 2, actor); err == nil {
		t.Fatal("stale resource accepted")
	} else {
		var e *identity.Error
		if !errors.As(err, &e) || e.Code != identity.Conflict {
			t.Fatal("conflict not typed")
		}
	}
	d, err := s.Doctor(ctx, "test transport")
	if err != nil || len(d.Checks) < 8 {
		t.Fatal("doctor missing foundation checks")
	}
}
