package application_test

import (
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
