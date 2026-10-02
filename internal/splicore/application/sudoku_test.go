package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/api"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/engine/xray"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/transportmask"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func sudokuSettings() v.Settings {
	return v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp", EngineOptions: &transportmask.Options{
		FinalMask: &transportmask.FinalMask{TCP: []transportmask.TCPMask{{Type: "sudoku", Settings: &transportmask.Sudoku{ASCII: "prefer_ascii", PaddingMin: 0, PaddingMax: 3}}}},
	}}
}
func composePhase7(e *xray.Engine) func() (*registry.Protocols, *registry.Engines, *registry.Exporters, error) {
	return func() (*registry.Protocols, *registry.Engines, *registry.Exporters, error) { return registry.Phase7(e) }
}
func TestSudokuFeatureRejectionBeforeAvailabilityAndPending(t *testing.T) {
	ctx := context.Background()
	e := xray.New(xray.Options{})
	defer e.Close(ctx)
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, composePhase7(e))
	defer stop(t, s, store)
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		code   identity.Code
		status int
	}{
		{"native", func(d map[string]any) { d["engine"] = "native" }, identity.UnsupportedEngineFeature, 422},
		{"reality", func(d map[string]any) { d["settings"].(map[string]any)["security"] = "reality" }, identity.UnsupportedEngineFeature, 422},
		{"tls", func(d map[string]any) { d["settings"].(map[string]any)["security"] = "tls" }, identity.UnsupportedEngineFeature, 422},
		{"vision", func(d map[string]any) { d["settings"].(map[string]any)["flow"] = "xtls-rprx-vision" }, identity.NotImplemented, 501},
		{"unknown-mask", func(d map[string]any) {
			d["settings"].(map[string]any)["engine_options"].(map[string]any)["finalmask"].(map[string]any)["tcp"].([]any)[0].(map[string]any)["type"] = "unknown"
		}, identity.Invalid, 400},
		{"null-options", func(d map[string]any) { d["settings"].(map[string]any)["engine_options"] = nil }, identity.Invalid, 400},
		{"raw-json", func(d map[string]any) { d["streamSettings"] = map[string]any{} }, identity.Invalid, 400},
		{"bad-secret", func(d map[string]any) { d["transport_secret"] = map[string]any{"password": "invalid"} }, identity.Invalid, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			var doc map[string]any
			_ = json.Unmarshal(xrayDocument(t, vlessDoc(t, freePort(t), sudokuSettings(), "")), &doc)
			test.mutate(doc)
			encoded, _ := json.Marshal(doc)
			for _, action := range []string{"validate", "plan", "apply"} {
				var body any = json.RawMessage(encoded)
				if action == "apply" {
					body = application.ApplyRequest{Document: encoded}
				}
				b, _ := json.Marshal(body)
				w := httptest.NewRecorder()
				api.Handler(s).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/creation/vless/"+action, bytes.NewReader(b)))
				var problem api.Problem
				if json.Unmarshal(w.Body.Bytes(), &problem) != nil || w.Code != test.status || problem.Code != test.code {
					t.Fatal("wrong feature rejection", action, w.Code, problem.Code)
				}
			}
		})
	}
	state, _ := store.State(ctx)
	inbounds, _ := store.Inbounds(ctx)
	if state.Revision != 0 || state.PendingTransactions != 0 || len(inbounds) != 0 || e.Status().Reason != "not_checked" {
		t.Fatal("invalid feature reached availability or authority")
	}
	page, err := s.Capabilities(ctx, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range page.Items {
		if p.Protocol != "vless" {
			continue
		}
		for _, engine := range p.EngineImplementations {
			for _, feature := range engine.Features.EngineFeatures {
				want := engine.Engine == "xray" && p.FeatureProfile == "plain" && engine.RuntimeImplemented
				if feature.Supported != want || feature.UDPQualified || feature.Security != "none" || feature.Flow != "none" {
					t.Fatal("feature composition overclaim")
				}
			}
			if engine.Engine == "xray" {
				for _, feature := range engine.NodeStatus.Features {
					if feature.Available {
						t.Fatal("missing artifact available")
					}
				}
			}
		}
	}
}
