package application_test

import (
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/registry/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/version"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type faultEngine struct {
	native.Engine
	stage  string
	handle *faultHandle
}

func (e faultEngine) Metadata() ports.EngineMetadata {
	return ports.EngineMetadata{ID: "native", Availability: ports.Compiled, RuntimeImplemented: true, ABI: 1, Protocols: []string{"snell", "hysteria2", "tuic", "vless"}}
}

func (e faultEngine) Compile(context.Context, ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if e.stage == "compile" {
		return nil, identity.Err(identity.Unavailable, "runtime construction fault")
	}
	return e.handle, nil
}

type faultHandle struct {
	stage  string
	closed bool
}

func (h *faultHandle) Start(context.Context) error {
	if h.stage == "start" {
		return identity.Err(identity.Unavailable, "start fault")
	}
	return nil
}
func (h *faultHandle) Health(context.Context) error {
	return identity.Err(identity.Unavailable, "health fault")
}
func (h *faultHandle) Activate()                   {}
func (h *faultHandle) Close(context.Context) error { h.closed = true; return nil }
func (h *faultHandle) Stats() ports.Stats          { return ports.Stats{} }
func TestRuntimeCreationStartHealthRollback(t *testing.T) {
	for _, stage := range []string{"compile", "start", "health"} {
		t.Run(stage, func(t *testing.T) {
			s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
			defer stop(t, s, store)
			p, _, x, _ := testfixture.Phase2()
			h := &faultHandle{stage: stage}
			eng, _ := registry.NewEngines(faultEngine{stage: stage, handle: h})
			fault, e := application.New(store, p, eng, x, version.Current())
			if e != nil {
				t.Fatal(e)
			}
			if e = fault.EnableRuntime(context.Background()); e != nil {
				t.Fatal(e)
			}
			defer fault.CloseRuntime(context.Background())
			d := doc(freePort(t), 5)
			plan, e := fault.PlanSnell(context.Background(), d)
			if e != nil {
				t.Fatal(e)
			}
			_, e = fault.ApplySnell(context.Background(), application.ApplyRequest{Document: d, Digest: plan.Digest, Revision: plan.Revision})
			if e == nil {
				t.Fatal("fault committed")
			}
			state, _ := store.State(context.Background())
			in, _ := store.Inbounds(context.Background())
			if state.Revision != 0 || state.PendingTransactions != 0 || len(in) != 0 || stage != "compile" && !h.closed {
				t.Fatal("fault rollback failed")
			}
		})
	}
}

type admissionRepo struct {
	ports.RuntimeRepository
	address string
	t       *testing.T
}

func (r admissionRepo) CommitOperation(ctx context.Context, op identity.Transaction, fn func(ports.Writer) error) error {
	c, e := net.DialTimeout("tcp", r.address, time.Second)
	if e != nil {
		r.t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = c.Read(make([]byte, 1)); !errors.Is(e, io.EOF) {
		r.t.Fatal("pending listener did not close the candidate socket", e)
	}
	return r.RuntimeRepository.CommitOperation(ctx, op, fn)
}
func TestPendingAdmissionClosed(t *testing.T) {
	port := freePort(t)
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), func(r ports.RuntimeRepository) ports.Repository {
		return admissionRepo{r, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), t}
	})
	defer stop(t, s, store)
	apply(t, s, doc(port, 5))
}
