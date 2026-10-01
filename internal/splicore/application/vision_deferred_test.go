package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/api"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/cli"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

type visionCountingEngine struct {
	faultEngine
	calls *atomic.Int64
}

func (e visionCountingEngine) Compile(context.Context, ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	e.calls.Add(1)
	return nil, identity.Err(identity.Unavailable, "unexpected runtime construction")
}

// Inject a missed creation validator without changing any dependency or runtime.
type visionBypassCodec struct{ v.Module }

func (m visionBypassCodec) DecodeCreation(b json.RawMessage) (ports.CreationDraft, error) {
	d, err := m.Module.DecodeCreation(b)
	if err != nil {
		return d, err
	}
	var settings v.Settings
	if err := json.Unmarshal(d.Settings, &settings); err != nil {
		return d, err
	}
	settings.Flow = v.Vision
	d.Settings, err = json.Marshal(settings)
	return d, err
}
func (visionBypassCodec) MaterializeCreation(d ports.CreationDraft) (ports.CreationDraft, error) {
	return d, nil
}
func (visionBypassCodec) ValidateInbound(access.Inbound) error { return nil }

func TestVisionRejectedAPIConfigImportCLIAndNoCommittedState(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.Phase5)
	defer stop(t, s, store)
	p, _, x, _ := registry.Phase5()
	var calls atomic.Int64
	engines, _ := registry.NewEngines(visionCountingEngine{calls: &calls})
	svc, err := application.New(store, p, engines, x, version.Current())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	defer svc.CloseRuntime(ctx)
	server := httptest.NewServer(api.Handler(svc))
	defer server.Close()
	client := transport.TestClient(server.Client(), server.URL)
	defer client.Close()

	for _, security := range []v.Security{v.Plain, v.TLS, v.Reality} {
		t.Run(string(security), func(t *testing.T) {
			d := vlessDoc(t, freePort(t), v.Settings{Security: security, Flow: v.Vision, Transport: "tcp", PacketEncoding: "xudp"}, "")
			for name, operation := range map[string]func() error{
				"validate": func() error { return client.ValidateCreation(ctx, "vless", d) },
				"plan":     func() error { _, err := client.PlanCreation(ctx, "vless", d); return err },
				"apply": func() error {
					_, err := client.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: d})
					return err
				},
			} {
				t.Run(name, func(t *testing.T) {
					var typed *identity.Error
					if err := operation(); !errors.As(err, &typed) || typed.Code != identity.NotImplemented {
						t.Fatalf("unexpected rejection: %v", err)
					}
				})
			}
			path := filepath.Join(t.TempDir(), "import.json")
			if err := os.WriteFile(path, d, 0600); err != nil {
				t.Fatal(err)
			}
			for _, command := range []string{"validate", "plan"} {
				var stdout, stderr bytes.Buffer
				if cli.Run(ctx, []string{"inbound", command, "--protocol", "vless", "--file", path}, &stdout, &stderr, cli.Dependencies{Queries: client}) == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "not_implemented") {
					t.Fatalf("CLI %s did not reject Vision", command)
				}
			}
			planPath := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(planPath, []byte(`{"digest":"unused","revision":"0"}`), 0600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if cli.Run(ctx, []string{"inbound", "apply", "--protocol", "vless", "--file", path, "--plan", planPath}, &stdout, &stderr, cli.Dependencies{Queries: client}) == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "not_implemented") {
				t.Fatal("CLI apply did not reject Vision")
			}
		})
	}
	state, err := store.State(ctx)
	inbounds, _ := store.Inbounds(ctx)
	if err != nil || state.Revision != 0 || state.PendingTransactions != 0 || len(inbounds) != 0 || calls.Load() != 0 {
		t.Fatal("rejected input reached state or runtime construction")
	}
}

func TestVisionMissedValidatorStillRollsBackBeforeRuntimeConstruction(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.Phase5)
	defer stop(t, s, store)
	p, err := registry.NewProtocols(visionBypassCodec{Module: v.Module{Security: v.Plain}})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	engines, _ := registry.NewEngines(visionCountingEngine{calls: &calls})
	_, _, exports, _ := registry.Phase5()
	svc, err := application.New(store, p, engines, exports, version.Current())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	defer svc.CloseRuntime(ctx)
	d := vlessDoc(t, freePort(t), v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}, "")
	plan, err := svc.PlanCreation(ctx, "vless", d)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: d, Digest: plan.Digest, Revision: plan.Revision})
	if err == nil {
		t.Fatal("missed validator committed Vision")
	}
	state, _ := store.State(ctx)
	inbounds, _ := store.Inbounds(ctx)
	if state.Revision != 0 || state.PendingTransactions != 0 || len(inbounds) != 0 || calls.Load() != 0 {
		t.Fatal("runtime guard failed to roll back before construction")
	}
}
