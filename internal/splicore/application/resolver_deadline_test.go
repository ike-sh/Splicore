package application_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolverFixtureBudget(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, tc := range []struct {
		name      string
		remaining time.Duration
		known     bool
		wantChild time.Duration
		wantGrace time.Duration
		wantError bool
	}{
		{name: "no-parent-deadline", wantChild: time.Minute, wantGrace: 2 * time.Second},
		{name: "long-parent-cap", remaining: 10 * time.Minute, known: true, wantChild: time.Minute, wantGrace: 2 * time.Second},
		{name: "parent-wins", remaining: time.Second, known: true, wantChild: 800 * time.Millisecond, wantGrace: 200 * time.Millisecond},
		{name: "minimum-launch-budget", remaining: 500 * time.Millisecond, known: true, wantChild: 400 * time.Millisecond, wantGrace: 100 * time.Millisecond},
		{name: "insufficient", remaining: 499 * time.Millisecond, known: true, wantError: true},
		{name: "expired", remaining: -time.Second, known: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := now.Add(tc.remaining)
			budget, err := resolverBudgetFor(now, parent, tc.known)
			if (err != nil) != tc.wantError {
				t.Fatal("budget error", err)
			}
			if err != nil {
				return
			}
			if budget.deadline.Sub(now) != tc.wantChild || budget.grace != tc.wantGrace || budget.waitDelay != tc.wantGrace/2 {
				t.Fatal("child deadline or cleanup reservation", budget)
			}
			if tc.known && (!budget.deadline.Before(parent) || budget.grace > tc.remaining/5 || !budget.deadline.Add(budget.grace).Before(parent.Add(time.Nanosecond))) {
				t.Fatal("child exceeds parent's usable lifetime", budget, parent)
			}
		})
	}
}

func TestResolverFixtureFailureCleanup(t *testing.T) {
	for _, name := range []string{"nonzero-exit", "cancellation"} {
		t.Run(name, func(t *testing.T) {
			const marker = "intentional resolver fixture failure"
			if os.Getenv(resolverFixtureScope) == t.Name() {
				if err := os.WriteFile(filepath.Join(t.TempDir(), "owned"), []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				if name == "cancellation" {
					t.Log(marker)
					select {} // The parent must cancel, reap, and remove this child's temp root.
				}
				t.Fatal(marker)
			}
			budget, err := resolverBudgetFor(time.Now(), time.Now().Add(3*time.Second), true)
			if err != nil {
				t.Fatal(err)
			}
			result := runResolverFixture(t.Context(), t.Name(), budget)
			var exit *exec.ExitError
			if !errors.As(result.err, &exit) || result.state == nil || result.state.Success() || result.pid <= 0 {
				t.Fatal("child failure was not returned and reaped", result.err, result.state, result.pid)
			}
			if !strings.Contains(string(result.output), marker) {
				t.Fatal("child did not reach the intended failure", string(result.output))
			}
			if name == "cancellation" {
				if !errors.Is(result.contextErr, context.DeadlineExceeded) {
					t.Fatal("child did not wait for cancellation", result.contextErr)
				}
			} else if result.contextErr != nil || result.state.ExitCode() != 1 {
				t.Fatal("unexpected child failure", result.contextErr, result.state)
			}
			if result.cleanupErr != nil || result.cleanedAt.Before(result.waitedAt) {
				t.Fatal("cleanup did not follow child reaping", result.cleanupErr)
			}
			if _, err = os.Stat(result.tempDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("child temporary directory survived cleanup", result.tempDir, err)
			}
			t.Logf("expected failure: pid=%d state=%v context=%v reaped=true temp_removed=true", result.pid, result.state, result.contextErr)
		})
	}
}
