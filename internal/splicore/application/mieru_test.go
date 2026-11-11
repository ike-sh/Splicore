package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func phase8Protocols() (*registry.Protocols, *registry.Engines, *registry.Exporters, error) {
	return registry.NativeCore()
}

type mieruFaultEngine struct{ faultEngine }

func (mieruFaultEngine) Metadata() ports.EngineMetadata {
	return ports.EngineMetadata{ID: "native", Availability: ports.Compiled, RuntimeImplemented: true, ABI: 1, Protocols: []string{"mieru"}}
}
func (mieruFaultEngine) Supports(ports.RuntimeIntent) error { return nil }
func mieruDoc(t *testing.T, port uint16) json.RawMessage {
	t.Helper()
	data, e := json.Marshal(map[string]any{"schema": 1, "name": "synthetic-mieru", "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "localhost", Port: port}, "settings": map[string]any{"transport": "tcp"}, "users": []any{map[string]any{"account_name": "Alice", "username": "synthetic-Alice", "password": "SyntheticAlicePasswordPhase8"}, map[string]any{"account_name": "Bob", "username": "synthetic-Bob", "password": "SyntheticBobPasswordPhase8"}}})
	if e != nil {
		t.Fatal(e)
	}
	return data
}
func applyMieru(t *testing.T, s *application.Service, d json.RawMessage) application.CreationResult {
	t.Helper()
	p, e := s.PlanCreation(context.Background(), "mieru", d)
	if e != nil {
		t.Fatal(e)
	}
	a, e := s.ApplyCreation(context.Background(), "mieru", application.ApplyRequest{Document: d, Digest: p.Digest, Revision: p.Revision})
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestMieruSQLiteRecoveryAndRollback(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "state", "state.db")
	var fault *hyCommitFault
	s, store := setupProtocols(t, path, func(r ports.MultiBindingRepository) ports.Repository {
		fault = &hyCommitFault{MultiBindingRepository: r}
		return fault
	}, phase8Protocols)
	closed := false
	defer func() {
		if !closed {
			stop(t, s, store)
		}
	}()
	a := applyMieru(t, s, mieruDoc(t, freePort(t)))
	view, e := s.Inbound(ctx, a.InboundID)
	if e != nil || view.Health != "healthy" || len(view.Bindings) != 2 {
		t.Fatal("healthy multi-user inbound", e)
	}
	safe, _ := json.Marshal(view)
	if strings.Contains(string(safe), "SyntheticAlicePasswordPhase8") || strings.Contains(fmt.Sprintf("%+v %#v", view, view), "SyntheticBobPasswordPhase8") {
		t.Fatal("ordinary state leaked credentials")
	}
	fault.fail = true
	b := a.Bindings[0]
	if _, e = s.SetBinding(ctx, a.InboundID, application.BindingRequest{BindingID: b.BindingID, Enabled: false, ResourceRevision: 1, Revision: 1}); e == nil {
		t.Fatal("storage fault committed")
	}
	view, e = s.Inbound(ctx, a.InboundID)
	state, _ := store.State(ctx)
	if e != nil || view.Health != "healthy" || state.Revision != 1 || state.PendingTransactions != 0 || !view.Bindings[0].Enabled {
		t.Fatal("rollback failed", e)
	}
	stop(t, s, store)
	closed = true
	for _, name := range []string{path, path + "-wal"} {
		data, e := os.ReadFile(name)
		if e != nil && os.IsNotExist(e) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(data), "SyntheticAlicePasswordPhase8") || strings.Contains(string(data), "SyntheticBobPasswordPhase8") {
			t.Fatal("SQLite plaintext leak")
		}
	}
	s, store = setupProtocols(t, path, nil, phase8Protocols)
	closed = false
	view, e = s.Inbound(ctx, a.InboundID)
	if e != nil || view.Health != "healthy" || len(view.Bindings) != 2 {
		t.Fatal("committed recovery", e)
	}
	for _, original := range a.Bindings {
		found := false
		for _, recovered := range view.Bindings {
			if recovered.BindingID == original.BindingID {
				found = true
			}
		}
		if !found {
			t.Fatal("committed binding identity changed")
		}
	}
	bindings, e := store.Bindings(ctx, a.InboundID)
	if e != nil {
		t.Fatal(e)
	}
	expected := map[string]string{"synthetic-Alice": "SyntheticAlicePasswordPhase8", "synthetic-Bob": "SyntheticBobPasswordPhase8"}
	for _, binding := range bindings {
		c, e := store.RevealCredential(ctx, binding.CredentialID)
		if e != nil {
			t.Fatal(e)
		}
		p, ok := c.Payload.(access.UsernamePasswordPayload)
		if !ok || expected[p.Username.Reveal()] != p.Password.Reveal() {
			t.Fatal("credential recovery changed")
		}
		delete(expected, p.Username.Reveal())
	}
	if len(expected) != 0 {
		t.Fatal("credential recovery missing user")
	}
}
func TestMieruInvalidConflictAndStorageFaultTransactions(t *testing.T) {
	for _, mode := range []string{"invalid", "credential", "port", "commit"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			var fault *hyCommitFault
			s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), func(r ports.MultiBindingRepository) ports.Repository {
				fault = &hyCommitFault{MultiBindingRepository: r}
				return fault
			}, phase8Protocols)
			defer stop(t, s, store)
			port := freePort(t)
			data := mieruDoc(t, port)
			if mode == "invalid" || mode == "credential" {
				var w map[string]any
				json.Unmarshal(data, &w)
				if mode == "invalid" {
					w["settings"] = map[string]any{"transport": "tcp", "mtu": 9999}
				} else {
					w["users"].([]any)[0].(map[string]any)["password"] = "short"
				}
				data, _ = json.Marshal(w)
				if _, e := s.PlanCreation(ctx, "mieru", data); e == nil {
					t.Fatal("invalid contract accepted")
				}
			} else {
				p, e := s.PlanCreation(ctx, "mieru", data)
				if e != nil {
					t.Fatal(e)
				}
				if mode == "port" {
					l, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
					if e != nil {
						t.Fatal(e)
					}
					defer l.Close()
				} else {
					fault.fail = true
				}
				_, e = s.ApplyCreation(ctx, "mieru", application.ApplyRequest{Document: data, Digest: p.Digest, Revision: p.Revision})
				if e == nil {
					t.Fatal("failed transaction committed")
				}
				if mode == "port" {
					var de *identity.Error
					if !errors.As(e, &de) || de.Code != identity.PortConflict {
						t.Fatal("untyped port conflict", e)
					}
				}
			}
			state, _ := store.State(ctx)
			all, _ := store.Inbounds(ctx)
			if state.Revision != 0 || state.PendingTransactions != 0 || len(all) != 0 {
				t.Fatal("failed transaction changed authority")
			}
		})
	}
}
func TestMieruStartupFaultRollback(t *testing.T) {
	for _, stage := range []string{"compile", "start", "health"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, phase8Protocols)
			defer stop(t, s, store)
			p, _, x, _ := phase8Protocols()
			h := &faultHandle{stage: stage}
			eng, _ := registry.NewEngines(mieruFaultEngine{faultEngine{stage: stage, handle: h}})
			svc, e := application.New(store, p, eng, x, version.Current())
			if e != nil {
				t.Fatal(e)
			}
			if e = svc.EnableRuntime(ctx); e != nil {
				t.Fatal(e)
			}
			defer svc.CloseRuntime(ctx)
			data := mieruDoc(t, freePort(t))
			plan, e := svc.PlanCreation(ctx, "mieru", data)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = svc.ApplyCreation(ctx, "mieru", application.ApplyRequest{Document: data, Digest: plan.Digest, Revision: plan.Revision}); e == nil {
				t.Fatal("startup failure committed")
			}
			state, _ := store.State(ctx)
			if state.Revision != 0 || state.PendingTransactions != 0 || stage != "compile" && !h.closed {
				t.Fatal("failed startup not rolled back")
			}
		})
	}
}
