package xray

import (
	"context"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
)

// Only proves the process ownership contract, not real kernel route protection.
// The pinned child + UID routing proof runs in the disposable kernel TUN lab.
type childProtectionFixture struct{}

func (childProtectionFixture) Capabilities() underlay.Capabilities {
	return underlay.Capabilities{Strategy: "test-child-owner", PerSocket: true, Child: true}
}
func (childProtectionFixture) Protect(context.Context, underlay.Scope, string, string, syscall.RawConn) error {
	return nil
}
func (childProtectionFixture) Reconcile(context.Context, []underlay.Endpoint) error { return nil }
func (childProtectionFixture) Verify(ctx context.Context) error                     { return ctx.Err() }

func TestUnderlayChildGenerationPIDAndRetirement(t *testing.T) {
	ctx := context.Background()
	f := underlay.NewWithBackend(childProtectionFixture{})
	l, err := f.Begin(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e := helperEngine(t, "echo")
	in := fixture(t)
	// Reserve the public listener independently for each iteration.
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	in.Inbound.Listeners[0].Endpoint.Port = uint16(reservation.Addr().(*net.TCPAddr).Port)
	reservation.Close()
	prepared, err := e.Compile(underlay.WithScope(underlay.WithFactory(ctx, f), underlay.Scope{Runtime: in.Inbound.ID, Generation: l.ID}), in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(*Handle)
	if err = h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	plan, status := h.underlay.Plan(), h.RuntimeStatus()
	if plan.Scope.Runtime != in.Inbound.ID || string(plan.Scope.Generation) != status.Generation || plan.PID != status.PID || !plan.InheritedProcessOwner {
		t.Fatal("child ownership not bound to actual generation/PID")
	}
	if err = h.underlay.Bind(l.ID, os.Getpid()); err == nil {
		t.Fatal("child ownership rebound")
	}
	h.Activate()
	roundTrip(t, h)
	if err = h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if h.underlay.Verify(ctx) == nil || h.underlay.Bind(l.ID, os.Getpid()) == nil {
		t.Fatal("retired child retained admission")
	}
	if err = h.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestUnderlayChildUnqualifiedFailsBeforeLaunch(t *testing.T) {
	x := testkit.NewUnderlay(t)
	ctx := context.Background()
	l, err := x.Factory.Begin(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e := helperEngine(t, "echo")
	if _, err = e.Compile(underlay.WithFactory(ctx, x.Factory), fixture(t)); err == nil {
		t.Fatal("unqualified child constructed")
	}
	if len(e.handles) != 0 {
		t.Fatal("failed construction retained child")
	}
	if _, err = e.Compile(ctx, fixture(t)); err == nil {
		t.Fatal("missing child provider accepted")
	}
	if err = (&underlay.ChildLease{}).Verify(ctx); err == nil {
		t.Fatal("unknown child accepted")
	}
}

func TestUnderlayChildBindingFailureJoinsSoleWaitOwner(t *testing.T) {
	f := underlay.NewWithBackend(childProtectionFixture{})
	l, err := f.Begin(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e := helperEngine(t, "echo")
	h := prepareHelper(t, e)
	h.underlay.Close()
	h.underlay, err = f.AcquireChild()
	if err != nil {
		t.Fatal(err)
	}
	command := e.command
	var launched *exec.Cmd
	e.command = func(path string, args ...string) *exec.Cmd {
		launched = command(path, args...)
		h.underlay.Close() // deterministic loss after preflight, before Bind
		return launched
	}
	if err = h.Start(context.Background()); err == nil {
		t.Fatal("retired binding admitted child")
	}
	if launched == nil || launched.ProcessState == nil {
		t.Fatal("binding failure did not join child Wait")
	}
	if err = h.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(h.RuntimeStatus().ConfigArtifact); !os.IsNotExist(err) {
		t.Fatal("failed child artifact leaked")
	}
}
