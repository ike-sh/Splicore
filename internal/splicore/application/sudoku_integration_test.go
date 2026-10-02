//go:build splicore_xray_integration

package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/engine/xray"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/transportmask"
	"github.com/sagernet/sing-box/internal/splicore/version"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestXrayPinnedSudokuSharedSecretExportAndRecovery(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	runtimeRoot := filepath.Join(root, "runtime")
	e := pinnedEngine(t, runtimeRoot)
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, composePhase7(e))
	closed := false
	defer func() {
		if !closed {
			stop(t, s, store)
		}
	}()
	password, err := transportmask.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	// Preserve exact imported case. The password is a string seed, not decoded hex.
	exact := strings.ToUpper(password.Reveal())
	var doc map[string]any
	_ = json.Unmarshal(xrayDocument(t, vlessDoc(t, freePort(t), sudokuSettings(), "")), &doc)
	doc["transport_secret"] = map[string]any{"password": exact}
	data, _ := json.Marshal(doc)
	plan, err := s.PlanCreation(ctx, "vless", data)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := s.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: data, Digest: plan.Digest, Revision: plan.Revision})
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.Inbound(ctx, applied.InboundID)
	if err != nil || view.Runtime == nil || view.Health != "healthy" {
		t.Fatal("masked runtime health", err)
	}
	old := *view.Runtime
	shared, err := store.RevealClientSharedCredentials(ctx, applied.InboundID)
	if err != nil || len(shared) != 1 || shared[0].Kind != access.Password || shared[0].OwnerInboundID == nil || *shared[0].OwnerInboundID != applied.InboundID || shared[0].Payload.(access.PasswordPayload).Password.Reveal() != exact {
		t.Fatal("shared secret ownership or migration")
	}
	ordinary, _ := json.Marshal(view)
	if strings.Contains(string(ordinary), exact) {
		t.Fatal("ordinary API leaked transport secret")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", shared, shared), exact) {
		t.Fatal("shared secret formatting leak")
	}
	bindings, err := store.Bindings(ctx, applied.InboundID)
	if err != nil || len(bindings) != 2 {
		t.Fatal("multi-user bindings")
	}
	for _, binding := range bindings {
		credential, _ := store.RevealCredential(ctx, binding.CredentialID)
		if credential.Kind != access.UUID || credential.OwnerAccountID == nil {
			t.Fatal("account UUID replaced by transport secret")
		}
		out, err := s.ExportClient(ctx, applied.InboundID, application.ExportRequest{Format: ports.Xray, ClientVersion: "26.3.27", BindingID: binding.ID})
		if err != nil || out.ContentShape != "xray-outbound" || !strings.Contains(out.Content, exact) || !strings.Contains(out.Content, credential.Payload.(access.UUIDPayload).UUID.Reveal()) {
			t.Fatal("authorized mask exporter", err)
		}
		for _, format := range []ports.Format{ports.Mihomo, ports.SingBox, ports.Surge, ports.URI} {
			if _, err := s.ExportClient(ctx, applied.InboundID, application.ExportRequest{Format: format, ClientVersion: "26.3.27", BindingID: binding.ID}); err == nil {
				t.Fatal("unsupported client emitted plain VLESS")
			}
		}
	}
	state, _ := store.State(ctx)
	if s.CloseRuntime(ctx) != nil {
		t.Fatal("masked stop")
	}
	if _, err := os.Stat(old.ConfigArtifact); !os.IsNotExist(err) {
		t.Fatal("ephemeral config retained")
	}
	p, eng, exports, err := composePhase7(e)()
	if err != nil {
		t.Fatal(err)
	}
	s, err = application.New(store, p, eng, exports, version.Current())
	if err != nil || s.EnableRuntime(ctx) != nil {
		t.Fatal("masked SQLite recovery", err)
	}
	view, err = s.Inbound(ctx, applied.InboundID)
	if err != nil || view.Runtime == nil || view.Runtime.Generation == old.Generation || view.Health != "healthy" {
		t.Fatal("new generation from SQLite")
	}
	after, _ := store.State(ctx)
	if after.Revision != state.Revision {
		t.Fatal("recovery changed committed revision")
	}
	again, _ := store.RevealClientSharedCredentials(ctx, applied.InboundID)
	if len(again) != 1 || again[0].ID != shared[0].ID || again[0].Payload.(access.PasswordPayload).Password.Reveal() != exact {
		t.Fatal("recovery changed shared secret")
	}
	if s.CloseRuntime(ctx) != nil || store.Close() != nil {
		t.Fatal("join and close")
	}
	closed = true
	db, err := os.ReadFile(filepath.Join(root, "state", "state.db"))
	if err != nil || strings.Contains(string(db), exact) {
		t.Fatal("SQLite plaintext transport secret")
	}
}

func TestXrayPinnedSudokuCommitCompensationAndRequiredMissing(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			runtimeRoot := filepath.Join(root, "runtime")
			e := pinnedEngine(t, runtimeRoot)
			port := freePort(t)
			wrap := func(repo ports.MultiBindingRepository) ports.Repository {
				return xrayCommitProbe{repo, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), t, fail}
			}
			s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), wrap, composePhase7(e))
			defer stop(t, s, store)
			d := xrayDocument(t, vlessDoc(t, port, sudokuSettings(), ""))
			plan, err := s.PlanCreation(ctx, "vless", d)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: d, Digest: plan.Digest, Revision: plan.Revision})
			state, _ := store.State(ctx)
			inbounds, _ := store.Inbounds(ctx)
			if fail {
				if err == nil || state.Revision != 0 || state.PendingTransactions != 0 || len(inbounds) != 0 {
					t.Fatal("masked commit compensation")
				}
				entries, _ := os.ReadDir(runtimeRoot)
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), "generation-") {
						t.Fatal("masked rollback retained artifact")
					}
				}
				l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
				if err != nil {
					t.Fatal("masked rollback retained listener")
				}
				_ = l.Close()
				return
			}
			if err != nil || s.CloseRuntime(ctx) != nil {
				t.Fatal("masked commit/close", err)
			}
			missing := xray.New(xray.Options{RuntimeDirectory: runtimeRoot})
			defer missing.Close(ctx)
			p, eng, exports, _ := composePhase7(missing)()
			failed, err := application.New(store, p, eng, exports, version.Current())
			if err != nil {
				t.Fatal(err)
			}
			if err = failed.EnableRuntime(ctx); err == nil || !strings.Contains(err.Error(), "unavailable") {
				t.Fatal("masked required artifact silently recovered", err)
			}
			system, err := failed.System(ctx)
			if err != nil || system.Health != "degraded" {
				t.Fatal("masked required unavailable status")
			}
			after, _ := store.State(ctx)
			if after.Revision != state.Revision {
				t.Fatal("failed recovery changed revision")
			}
		})
	}
}
