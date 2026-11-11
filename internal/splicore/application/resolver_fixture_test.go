package application_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const resolverFixtureScope = "SPLICORE_TEST_RESOLVER_SCOPE"

var resolverFixtureQueries atomic.Int64

type resolverBudget struct {
	deadline  time.Time
	grace     time.Duration
	waitDelay time.Duration
}

func resolverBudgetFor(now, parentDeadline time.Time, parentKnown bool) (resolverBudget, error) {
	const maximumGrace = 2 * time.Second
	budget := resolverBudget{deadline: now.Add(time.Minute), grace: maximumGrace}
	if parentKnown {
		remaining := parentDeadline.Sub(now)
		// Reserve one fifth (at most two seconds) for kill/reap, pipe closure,
		// and reporting. Below 100ms of grace, refuse to launch a process.
		budget.grace = min(maximumGrace, remaining/5)
		if budget.grace < 100*time.Millisecond {
			return resolverBudget{}, fmt.Errorf("resolver fixture budget: remaining=%s cannot reserve cleanup grace >=100ms", remaining)
		}
		budget.deadline = minTime(budget.deadline, parentDeadline.Add(-budget.grace))
	}
	// Pipe draining may consume only half the grace; the remainder is kept
	// for process observation, test cleanups, and reporting before the alarm.
	budget.waitDelay = budget.grace / 2
	return budget, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

type resolverResult struct {
	output     []byte
	err        error
	contextErr error
	pid        int
	state      *os.ProcessState
	startedAt  time.Time
	waitedAt   time.Time
	tempDir    string
	cleanupErr error
	cleanedAt  time.Time
}

func runResolverFixture(parent context.Context, name string, budget resolverBudget) (result resolverResult) {
	ctx, cancel := context.WithDeadline(parent, budget.deadline)
	defer cancel()
	remaining := time.Until(budget.deadline)
	if ctx.Err() != nil || remaining < 50*time.Millisecond {
		return resolverResult{err: fmt.Errorf("resolver fixture budget: child execution window=%s context=%v", remaining, ctx.Err()), contextErr: ctx.Err(), waitedAt: time.Now()}
	}
	result.tempDir, result.err = os.MkdirTemp("", "splicore-resolver-")
	if result.err != nil {
		return result
	}
	// The parent owns the child's temp root, so forced termination does not
	// strand t.TempDir resources that the child cannot clean after a kill.
	defer func() {
		result.cleanupErr = os.RemoveAll(result.tempDir)
		result.cleanedAt = time.Now()
	}()
	parts := strings.Split(name, "/")
	for i, part := range parts {
		parts[i] = "^" + regexp.QuoteMeta(part) + "$"
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run="+strings.Join(parts, "/"), "-test.count=1", "-test.v=true", "-test.timeout="+remaining.String())
	cmd.Env = append(os.Environ(), resolverFixtureScope+"="+name, "TMPDIR="+result.tempDir, "TMP="+result.tempDir, "TEMP="+result.tempDir)
	cmd.WaitDelay = budget.waitDelay
	result.startedAt = time.Now()
	// CombinedOutput calls Run/Wait even after context cancellation. No return
	// path after a successful Start bypasses reaping the direct child.
	result.output, result.err = cmd.CombinedOutput()
	result.waitedAt = time.Now()
	result.contextErr = ctx.Err()
	result.state = cmd.ProcessState
	if cmd.Process != nil {
		result.pid = cmd.Process.Pid
	}
	return result
}

func TestMain(m *testing.M) {
	if os.Getenv(resolverFixtureScope) != "" {
		// This child runs one resolver scenario. Install before any test/runtime
		// starts and keep the pointer immutable until process exit. The parent
		// and other test instances never share this resolver or its counter.
		net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			resolverFixtureQueries.Add(1)
			return nil, net.InvalidAddrError("ambient DNS forbidden")
		}}
	}
	os.Exit(m.Run())
}

// isolatedResolver runs the complete scenario in a fresh copy of this test
// executable, including race instrumentation. A nil return means that the
// parent has waited for the child's assertions and cleanup; its caller returns.
func isolatedResolver(t *testing.T) *atomic.Int64 {
	t.Helper()
	if os.Getenv(resolverFixtureScope) == t.Name() {
		t.Logf("resolver fixture active: %s", t.Name())
		return &resolverFixtureQueries
	}
	previous := net.DefaultResolver
	parentDeadline, parentKnown := t.Deadline()
	budget, err := resolverBudgetFor(time.Now(), parentDeadline, parentKnown)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("resolver fixture budget: parent_known=%t parent_deadline=%s child_deadline=%s cleanup_grace=%s wait_delay=%s", parentKnown, parentDeadline.Format(time.RFC3339Nano), budget.deadline.Format(time.RFC3339Nano), budget.grace, budget.waitDelay)
	result := runResolverFixture(t.Context(), t.Name(), budget)
	t.Logf("resolver fixture exit: pid=%d waited=%t started_at=%s waited_at=%s context=%v state=%v temp_dir=%s cleanup_error=%v cleaned_at=%s", result.pid, result.state != nil, result.startedAt.Format(time.RFC3339Nano), result.waitedAt.Format(time.RFC3339Nano), result.contextErr, result.state, result.tempDir, result.cleanupErr, result.cleanedAt.Format(time.RFC3339Nano))
	t.Logf("isolated resolver child:\n%s", result.output)
	if result.err != nil || result.contextErr != nil || result.cleanupErr != nil {
		t.Fatalf("resolver scenario failed: %v; context: %v; cleanup: %v", result.err, result.contextErr, result.cleanupErr)
	}
	if !bytes.Contains(result.output, []byte("resolver fixture active: "+t.Name())) {
		t.Fatal("child did not execute the resolver scenario")
	}
	if net.DefaultResolver != previous {
		t.Fatal("child changed the parent's resolver")
	}
	return nil
}

func TestResolverFixtureIsolation(t *testing.T) {
	for i := range 4 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			ambient := isolatedResolver(t)
			if ambient == nil {
				return
			}
			if ambient.Load() != 0 {
				t.Fatal("inherited another scenario's DNS queries")
			}
			if _, err := net.DefaultResolver.LookupIP(t.Context(), "ip", "ambient.fixture.invalid"); err == nil || ambient.Load() == 0 {
				t.Fatal("sentinel did not reject and observe a real ambient lookup", err)
			}
		})
	}
}
