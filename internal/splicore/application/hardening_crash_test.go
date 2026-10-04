package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/engine/native"
	"github.com/sagernet/sing-box/internal/splicore/nodeimport"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/storage/sqlite"
)

// Faults live only in interface wrappers in the child. Exit bypasses every
// cleanup defer and leaves real SQLite/WAL/installation ownership to recovery.
type phase15Crash struct {
	stage        string
	expectedRoot string
	armed        atomic.Bool
}

func (f *phase15Crash) at(stage string) {
	if f.armed.Load() && f.stage == stage {
		os.Exit(77)
	}
}

type phase15CrashRepo struct {
	*sqlite.Store
	fault *phase15Crash
}

func (r *phase15CrashRepo) CommitOperation(ctx context.Context, op identity.Transaction, fn func(ports.Writer) error) error {
	err := r.Store.CommitOperation(ctx, op, func(w ports.Writer) error {
		if err := fn(w); err != nil {
			return err
		}
		r.fault.at("before-commit")
		return nil
	})
	if err == nil && r.fault.armed.Load() && r.fault.stage == "after-commit" {
		if root := r.fault.expectedRoot; root != "" {
			state, e := r.Store.ClientState(ctx)
			if e != nil {
				return e
			}
			b, e := json.Marshal(state)
			if e != nil {
				return e
			}
			if e = os.WriteFile(filepath.Join(root, "expected.json"), b, 0600); e != nil {
				return e
			}
		}
		r.fault.at("after-commit")
	}
	return err
}

type phase15CrashFactory struct {
	native.SnellOutboundFactory
	fault *phase15Crash
}

func (f phase15CrashFactory) Build(context.Context, client.RemoteNode, access.Credential) (ports.ClientDialer, error) {
	f.fault.at("prepare")
	return phase15CrashDialer{f.fault}, nil
}

type phase15CrashDialer struct{ fault *phase15Crash }

func (phase15CrashDialer) DialContext(context.Context, access.Endpoint) (net.Conn, error) {
	return nil, identity.Err(identity.Unavailable, "synthetic no-I/O adapter")
}
func (d phase15CrashDialer) Close() error { d.fault.at("before-retirement"); return nil }

func TestPhase15ProcessRuntimeCrashWindows(t *testing.T) {
	if root := os.Getenv("SPLICORE_PHASE15_CRASH_ROOT"); root != "" {
		phase15RuntimeCrashChild(t, root, os.Getenv("SPLICORE_PHASE15_CRASH_STAGE"))
		t.Fatal("crash did not execute")
	}
	for _, stage := range []string{"before-commit", "after-commit", "prepare", "after-activation", "before-retirement", "proxy-fetch", "ruleset-fetch", "proxy-commit", "ruleset-commit"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPhase15ProcessRuntimeCrashWindows$")
			command.Env = append(os.Environ(), "SPLICORE_PHASE15_CRASH_ROOT="+root, "SPLICORE_PHASE15_CRASH_STAGE="+stage)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("fault not reached: %v\n%s", err, output)
			}
			b, err := os.ReadFile(filepath.Join(root, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			var expected client.ProfileState
			if err = json.Unmarshal(b, &expected); err != nil {
				t.Fatal(err)
			}
			s, store := setupSnell(t, filepath.Join(root, "state", "state.db"), nil)
			defer stop(t, s, store)
			enableClient(t, s)
			status, err := s.ClientStatus(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(status.State, expected) || status.Health != "healthy" {
				t.Fatalf("SQLite authority not recovered: revision=%d expected=%d health=%s", status.State.Revision, expected.Revision, status.Health)
			}
			db, err := store.State(ctx)
			if err != nil || db.PendingTransactions != 0 {
				t.Fatal("pending operation not reconciled", err)
			}
			if status.Underlay.Health != "healthy" || status.Underlay.Unprotected != 0 {
				t.Fatal("recovery lost lease ownership")
			}
			doctor, err := s.Doctor(ctx, "local-test")
			if err != nil {
				t.Fatal(err)
			}
			for _, check := range doctor.Checks {
				if check.Name == "runtime_consistency" && check.Status != "pass" {
					t.Fatal(check)
				}
			}
		})
	}
}

func phase15RuntimeCrashChild(t *testing.T, root, stage string) {
	fault := &phase15Crash{stage: stage}
	s, store := setupSnell(t, filepath.Join(root, "state", "state.db"), func(repo ports.RuntimeRepository) ports.Repository {
		return &phase15CrashRepo{repo.(*sqlite.Store), fault}
	})
	factories, err := registry.NewOutbounds(phase15CrashFactory{fault: fault})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(context.Background(), factories); err != nil {
		t.Fatal(err)
	}
	if stage == "proxy-fetch" || stage == "ruleset-fetch" || stage == "proxy-commit" || stage == "ruleset-commit" {
		phase15ProviderCrashChild(t, s, store, root, stage, fault)
		return
	}
	psk, err := snell.GeneratePSK()
	if err != nil {
		t.Fatal(err)
	}
	node := addNode(t, s, access.Endpoint{Host: "127.0.0.1", Port: 1}, 6, psk.Reveal())
	addProxy(t, s, node)
	expected, err := store.ClientState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stage == "after-commit" || stage == "after-activation" || stage == "before-retirement" {
		expected.Revision++
	}
	phase15WriteExpected(t, root, expected)
	fault.armed.Store(true)
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "restart"})
	fault.at("after-activation")
}

func phase15WriteExpected(t *testing.T, root string, state client.ProfileState) {
	t.Helper()
	b, err := json.Marshal(state)
	if err == nil {
		err = os.WriteFile(filepath.Join(root, "expected.json"), b, 0600)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// A committed replacement includes provider generation, RuleSet/node identity,
// encrypted sources and validators in the same transaction. The parent has no
// live feed and must reconstruct it entirely from SQLite.
func phase15ProviderCrashChild(t *testing.T, s *application.Service, store *sqlite.Store, root, stage string, fault *phase15Crash) {
	kind := "proxy"
	format := "canonical"
	if stage == "ruleset-fetch" || stage == "ruleset-commit" {
		kind = "ruleset"
		format = "canonical-rules"
	}
	feed := phase15CrashFeed(t, kind, stage)
	defer feed.Close()
	p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "owned-crash-feed", Kind: kind, Format: format, AllowPrivate: true}, Source: &provider.Source{URL: feed.URL}})
	expected, err := store.ClientState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	phase15WriteExpected(t, root, expected)
	if stage == "proxy-fetch" || stage == "ruleset-fetch" {
		_, _ = s.RefreshProvider(context.Background(), p.ProviderID)
		t.Fatal("fetch fault not reached")
	}
	preview, err := s.PreviewProviderRefresh(context.Background(), p.ProviderID)
	if err != nil || !preview.Applicable {
		t.Fatal(err, preview.Reason)
	}
	// Capture exact committed state inside the repository wrapper, before exiting.
	fault.stage = "after-commit"
	fault.armed.Store(true)
	// The wrapper's snapshot observer writes expected authority after successful commit.
	fault.expectedRoot = root
	_, _ = s.ApplyManagement(context.Background(), application.ManagementApply{Token: preview.Token, Revision: preview.Revision})
}

func phase15CrashFeed(t *testing.T, kind, stage string) *httptest.Server {
	t.Helper()
	body := `{"schema_version":1,"rules":[{"domain_suffixes":["owned.test"]}]}`
	if kind == "proxy" {
		psk, err := snell.GeneratePSK()
		if err != nil {
			t.Fatal(err)
		}
		body = feedDocument([]nodeimport.Candidate{snellCandidate("owned", access.Endpoint{Host: "127.0.0.1", Port: 1}, psk.Reveal())})
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stage == "proxy-fetch" || stage == "ruleset-fetch" {
			os.Exit(77)
		}
		_, _ = w.Write([]byte(body))
	}))
}
