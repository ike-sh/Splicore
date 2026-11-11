package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

func TestRuntimeBoundaryRegistryAndImport(t *testing.T) {
	p, e, _, err := registry.NativeCore()
	if err != nil {
		t.Fatal(err)
	}
	if keys := e.Keys(); len(keys) != 1 || keys[0] != "native" {
		t.Fatal("runtime boundary", keys)
	}
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
	defer stop(t, s, store)
	enableClient(t, s)
	ctx := context.Background()
	for _, engine := range []string{"xray", "unknown"} {
		doc := map[string]any{"schema": 1, "engine": engine, "name": "retired", "listener": map[string]any{"host": "127.0.0.1", "port": 12345}, "display_endpoint": map[string]any{"host": "localhost", "port": 12345}, "settings": map[string]any{"security": "none", "flow": "none", "transport": "tcp", "packet_encoding": "xudp"}, "users": []any{map[string]any{"account_name": "Alice"}}}
		b, _ := json.Marshal(doc)
		var typed *identity.Error
		if _, err = p.DecodeCreation(e, "vless", b); !errors.As(err, &typed) || typed.Code != identity.UnsupportedEngineForProtocol {
			t.Fatal("removed engine admitted", err)
		}
	}
	candidate := snellCandidate("stable", access.Endpoint{Host: "localhost", Port: 443}, "synthetic-credential")
	for _, field := range []string{"engine", "finalmask", "sudoku"} {
		b, _ := json.Marshal(nodeimport.Document{Schema: 1, Nodes: []nodeimport.Candidate{candidate}})
		var doc map[string]any
		json.Unmarshal(b, &doc)
		node := doc["nodes"].([]any)[0].(map[string]any)
		if field == "engine" {
			node[field] = "xray"
		} else {
			node[field] = map[string]any{}
		}
		b, _ = json.Marshal(doc)
		preview, err := s.PreviewManagement(ctx, application.ManagementRequest{Operation: "import", InputFormat: "canonical", Content: string(b), GenerateOutbounds: true})
		if err != nil || preview.Applicable || len(preview.Entries) != 1 || preview.Entries[0].Kind != "Unsupported" {
			t.Fatal("retired capability preview", field, err, preview)
		}
		if _, err = s.ApplyManagement(ctx, application.ManagementApply{Token: preview.Token, Revision: preview.Revision}); err == nil {
			t.Fatal("unsupported preview applied")
		}
	}
	status, err := s.ClientStatus(ctx)
	if err != nil || len(status.State.Nodes) != 0 || len(status.State.Outbounds) != 1 {
		t.Fatal("unsupported import created runnable state", err)
	}
}
