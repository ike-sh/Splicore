package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/api"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/engine/xray"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/registry"
)

func xrayDocument(t *testing.T, doc json.RawMessage) json.RawMessage {
	t.Helper()
	var d map[string]json.RawMessage
	if json.Unmarshal(doc, &d) != nil {
		t.Fatal("document")
	}
	d["engine"] = json.RawMessage(`"xray"`)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestXrayStrictPolicyTypedRejectionPreservesAuthority(t *testing.T) {
	ctx := context.Background()
	e := xray.New(xray.Options{})
	defer e.Close(ctx)
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, composeXray(e))
	defer stop(t, s, store)
	document := xrayDocument(t, vlessDoc(t, freePort(t), v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}, ""))
	var input map[string]any
	if json.Unmarshal(document, &input) != nil {
		t.Fatal("document")
	}
	for _, limit := range []string{"quota_bytes", "upload_bps", "download_bps"} {
		input["users"].([]any)[0].(map[string]any)["traffic_policy"] = map[string]any{limit: 100}
		strict, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		for _, action := range []string{"validate", "plan", "apply"} {
			var body any = json.RawMessage(strict)
			if action == "apply" {
				body = application.ApplyRequest{Document: strict}
			}
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			api.Handler(s).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/creation/vless/"+action, bytes.NewReader(b)))
			var problem api.Problem
			if json.Unmarshal(w.Body.Bytes(), &problem) != nil || w.Code != http.StatusUnprocessableEntity || problem.Code != identity.UnsupportedPolicyForEngine {
				t.Fatalf("%s/%s did not reject unsupported enforcement", limit, action)
			}
		}
	}
	state, err := store.State(ctx)
	if err != nil || state.Revision != 0 || state.PendingTransactions != 0 {
		t.Fatal("policy rejection changed authority", err)
	}
	inbounds, err := store.Inbounds(ctx)
	if err != nil || len(inbounds) != 0 || e.Status().Reason != "not_checked" {
		t.Fatal("policy rejection reached engine availability/runtime", err)
	}
	input["users"].([]any)[0].(map[string]any)["traffic_policy"] = map[string]any{"quota_bytes": -1}
	bad, _ := json.Marshal(input)
	var problem *identity.Error
	if err := s.ValidateCreation(ctx, "vless", bad); !errors.As(err, &problem) || problem.Code != identity.Invalid {
		t.Fatal("invalid policy must remain a domain error")
	}
	input["users"].([]any)[0].(map[string]any)["traffic_policy"] = map[string]any{"quota_bytes": 100}
	input["policy_mode"] = "metadata_only"
	metadata, _ := json.Marshal(input)
	p, engines, _, err := composeXray(e)()
	if err != nil {
		t.Fatal(err)
	}
	draft, err := p.DecodeCreation(engines, "vless", metadata)
	if err != nil || draft.Users[0].Policy == nil || *draft.Users[0].Policy.QuotaBytes != 100 {
		t.Fatal("explicit metadata policy lost", err)
	}
}
func composeXray(e *xray.Engine) func() (*registry.Protocols, *registry.Engines, *registry.Exporters, error) {
	return func() (*registry.Protocols, *registry.Engines, *registry.Exporters, error) { return registry.Phase6(e) }
}
func TestXrayMissingOptionalArtifactCapabilitiesAndFailClosed(t *testing.T) {
	ctx := context.Background()
	e := xray.New(xray.Options{})
	defer e.Close(ctx)
	_ = e.ValidateAvailability(ctx)
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, composeXray(e))
	defer stop(t, s, store)
	system, err := s.System(ctx)
	if err != nil || system.Health != "healthy" {
		t.Fatal("optional artifact must not fail native-only startup", err)
	}
	page, err := s.Capabilities(ctx, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range page.Items {
		for _, engine := range p.EngineImplementations {
			if engine.Engine == "xray" && p.Availability == ports.Compiled {
				if !engine.RuntimeImplemented || engine.NodeStatus.Available || !engine.Features.TCP || engine.Features.PerUserStats || engine.Features.NativeStats != ports.Unsupported || engine.Features.Vision || engine.Features.HotUserUpdate {
					t.Fatal("effective xray capability", engine)
				}
			}
		}
	}
	d := xrayDocument(t, vlessDoc(t, freePort(t), v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}, ""))
	if s.ValidateCreation(ctx, "vless", d) == nil {
		t.Fatal("missing engine validate")
	}
	if _, err = s.PlanCreation(ctx, "vless", d); err == nil {
		t.Fatal("missing engine plan")
	}
	if _, err = s.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: d}); err == nil {
		t.Fatal("missing engine apply")
	}
	state, _ := store.State(ctx)
	inbounds, _ := store.Inbounds(ctx)
	if state.Revision != 0 || state.PendingTransactions != 0 || len(inbounds) != 0 {
		t.Fatal("missing artifact changed authority")
	}
	var bad map[string]any
	_ = json.Unmarshal(d, &bad)
	bad["settings"].(map[string]any)["flow"] = "xtls-rprx-vision"
	vision, _ := json.Marshal(bad)
	if err = s.ValidateCreation(ctx, "vless", vision); err == nil || !strings.Contains(err.Error(), "not_implemented") {
		t.Fatal("Vision gate")
	}
	bad["settings"].(map[string]any)["flow"] = "none"
	bad["users"].([]any)[0].(map[string]any)["traffic_policy"] = map[string]any{"quota_bytes": 100}
	strict, _ := json.Marshal(bad)
	var policyError *identity.Error
	if err = s.ValidateCreation(ctx, "vless", strict); !errors.As(err, &policyError) || policyError.Code != identity.UnsupportedPolicyForEngine {
		t.Fatal("strict policy must reject before availability")
	}
}
