package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/cli"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	sm "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
)

type managementCommitFault struct {
	*sqlite.Store
	fail atomic.Bool
}

func (r *managementCommitFault) CommitOperation(ctx context.Context, op identity.Transaction, fn func(ports.Writer) error) error {
	return r.Store.CommitOperation(ctx, op, func(w ports.Writer) error {
		if err := fn(w); err != nil {
			return err
		}
		if r.fail.Load() {
			return identity.Err(identity.Unavailable, "synthetic management commit failure")
		}
		return nil
	})
}

func TestPhase14CommitRollbackAndRevisionSafety(t *testing.T) {
	ctx := context.Background()
	var fault *managementCommitFault
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), func(r ports.RuntimeRepository) ports.Repository {
		fault = &managementCommitFault{Store: r.(*sqlite.Store)}
		return fault
	})
	defer stop(t, s, store)
	enableClient(t, s)
	remote := freePort(t)
	created := apply(t, s, doc(remote, 6))
	psk := remotePSK(t, store, created.InboundID)
	feed := &managementFeed{}
	feed.set(feedDocument([]nodeimport.Candidate{snellCandidate("stable", access.Endpoint{Host: "127.0.0.1", Port: remote}, psk)}), "validator-one", 0)
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "rollback", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: fixture.URL, Auth: &provider.Auth{Type: "bearer", Value: "PRIVATE_AUTH"}}})
	if _, err := s.RefreshProvider(ctx, p.ProviderID); err != nil {
		t.Fatal(err)
	}
	n := providerNodes(t, s, p.ProviderID)[0]
	status, _ := s.ClientStatus(ctx)
	var oid identity.ID
	for _, o := range status.State.Outbounds {
		if o.NodeID != nil && *o.NodeID == n.ID {
			oid = o.ID
		}
	}
	local := freePort(t)
	addLocal(t, s, local, oid)
	target := echoTarget(t, "127.0.0.1")
	before, _ := s.ClientStatus(ctx)
	sourceBefore, _ := store.RevealProviderSource(ctx, p.ProviderID)
	feed.set(feedDocument([]nodeimport.Candidate{snellCandidate("stable", n.Endpoint, "replacement-synthetic-password")}), "validator-two", 0)
	p, err := s.PreviewProviderRefresh(ctx, p.ProviderID)
	if err != nil || !p.Applicable {
		t.Fatal(err, p.Reason)
	}
	fault.fail.Store(true)
	if _, err = s.ApplyManagement(ctx, application.ManagementApply{Token: p.Token, Revision: p.Revision}); err == nil {
		t.Fatal("failed commit accepted")
	}
	fault.fail.Store(false)
	after, _ := s.ClientStatus(ctx)
	sourceAfter, _ := store.RevealProviderSource(ctx, p.ProviderID)
	if !reflect.DeepEqual(before.State, after.State) || !reflect.DeepEqual(sourceBefore, sourceAfter) {
		t.Fatal("failed transaction changed canonical state or validators")
	}
	if err = transfer(local, target, []byte("old-generation-after-rollback")); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, s)
	if _, err = s.ApplyManagement(ctx, application.ManagementApply{Token: p.Token, Revision: p.Revision}); err == nil {
		t.Fatal("consumed plan reused")
	}
	feed.set(feedDocument([]nodeimport.Candidate{snellCandidate("stable", n.Endpoint, psk)}), "validator-three", 0)
	p, err = s.PreviewProviderRefresh(ctx, n.Provenance.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	managementApply(t, s, application.ManagementRequest{Operation: "batch", Action: "metadata", IDs: []identity.ID{n.ID}, Metadata: identity.Metadata{"folder": "moved"}})
	if _, err = s.ApplyManagement(ctx, application.ManagementApply{Token: p.Token, Revision: p.Revision}); err == nil {
		t.Fatal("stale revision applied")
	}
	current := providerNodes(t, s, n.Provenance.ProviderID)[0]
	if current.ID != n.ID || current.Provenance != n.Provenance || current.Metadata["folder"] != "moved" {
		t.Fatal("metadata changed ownership")
	}
}

func TestPhase14APICLISecretBoundaryAndManualDedup(t *testing.T) {
	ctx := context.Background()
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
	defer stop(t, s, store)
	enableClient(t, s)
	feed := &managementFeed{}
	feed.set("INVALID_FEED_WITH_SECRET", "", 0)
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "safe-display", Kind: "proxy", Format: "canonical", AllowPrivate: true}, Source: &provider.Source{URL: fixture.URL + "/SOURCE_SECRET?token=QUERY_SECRET", Auth: &provider.Auth{Type: "bearer", Value: "AUTH_SECRET"}}})
	handler := api.Handler(s)
	for _, path := range []string{"/api/v1/providers", "/api/v1/providers/" + string(p.ProviderID), "/api/v1/system"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
		for _, secret := range []string{"SOURCE_SECRET", "QUERY_SECRET", "AUTH_SECRET", "INVALID_FEED_WITH_SECRET"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("passive API secret")
			}
		}
	}
	for _, operation := range []struct{ method, suffix string }{{"DELETE", ""}, {"POST", "/refresh"}, {"POST", "/refresh-preview"}} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(operation.method, "/api/v1/rule-set-providers/"+string(p.ProviderID)+operation.suffix, strings.NewReader("{}")))
		if w.Code != 404 {
			t.Fatal("wrong resource kind accepted", w.Code)
		}
	}
	if _, err := s.RefreshProvider(ctx, p.ProviderID); err == nil {
		t.Fatal("invalid feed accepted")
	}
	status, _ := s.ClientStatus(ctx)
	if status.State.Management.Providers[0].LastError != "parse_failed" {
		t.Fatal("wrong error phase")
	}
	var out, errors bytes.Buffer
	deps := cli.Dependencies{Queries: s}
	if cli.Run(ctx, []string{"provider", "list"}, &out, &errors, deps) != 0 {
		t.Fatal(errors.String())
	}
	if strings.Contains(out.String()+errors.String(), "SOURCE_SECRET") || strings.Contains(fmt.Sprintf("%+v", provider.Source{URL: "SECRET"}), "SECRET") {
		t.Fatal("CLI secret")
	}
	if cli.Run(ctx, []string{"ruleset-provider", "delete", "--id", string(p.ProviderID)}, &out, &errors, deps) == 0 {
		t.Fatal("CLI wrong kind")
	}
	if cli.Run(ctx, []string{"node", "import-uri", "vless://ARG_SECRET@host"}, &out, &errors, deps) == 0 || strings.Contains(errors.String(), "ARG_SECRET") {
		t.Fatal("URI argv leaked")
	}
	remote := freePort(t)
	created := apply(t, s, doc(remote, 5))
	psk := remotePSK(t, store, created.InboundID)
	one := snellCandidate("one", access.Endpoint{Host: "127.0.0.1", Port: remote}, psk)
	one.Node.Protocol = sm.Key(5)
	one.Node.Options.Data = []byte(`{"version":5}`)
	two := one
	two.Key = "two"
	file := filepath.Join(t.TempDir(), "import.json")
	if err := os.WriteFile(file, []byte(feedDocument([]nodeimport.Candidate{one, two})), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errors.Reset()
	if cli.Run(ctx, []string{"node", "import", "--file", file, "--generate-outbounds"}, &out, &errors, deps) != 0 {
		t.Fatal(errors.String())
	}
	var preview application.ManagementPreview
	if json.Unmarshal(out.Bytes(), &preview) != nil || !preview.Applicable {
		t.Fatal("duplicate candidates failed")
	}
	if strings.Contains(out.String(), psk) {
		t.Fatal("preview contains secret")
	}
	if _, err := s.ApplyManagement(ctx, application.ManagementApply{Token: preview.Token, Revision: preview.Revision}); err != nil {
		t.Fatal(err)
	}
	status, _ = s.ClientStatus(ctx)
	if len(status.State.Nodes) != 1 {
		t.Fatal("exact duplicates not deduped")
	}
	exported, err := s.ExportNodes(ctx, application.NodeExportRequest{All: true, Format: "mihomo", ClientVersion: "1.19.30", RevealSecrets: true})
	if err != nil || len(exported.Details) != 1 || exported.Details[0].Description.ServerVersion != 5 || exported.Details[0].Description.ClientWireVersion != 4 {
		t.Fatal("export version mapping missing", err)
	}
	if !strings.Contains(exported.Content, `"proxies"`) {
		t.Fatal("export is not proxies fragment")
	}
	// Preserve the existing node CRUD --file/--plan flow alongside token apply.
	node := status.State.Nodes[0]
	node.Name = "renamed-through-existing-cli"
	mutation, err := json.Marshal(application.ClientMutation{Resource: "node", Action: "update", ID: node.ID, Node: &node})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.PlanClient(ctx, mutation)
	if err != nil {
		t.Fatal(err)
	}
	planBytes, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	planFile := filepath.Join(t.TempDir(), "existing-plan.json")
	if os.WriteFile(file, mutation, 0600) != nil || os.WriteFile(planFile, planBytes, 0600) != nil {
		t.Fatal("CLI fixture write")
	}
	out.Reset()
	errors.Reset()
	if cli.Run(ctx, []string{"node", "apply", "--file", file, "--plan", planFile}, &out, &errors, deps) != 0 {
		t.Fatal("existing CRUD CLI apply", errors.String())
	}
	status, _ = s.ClientStatus(ctx)
	if status.State.Nodes[0].Name != node.Name {
		t.Fatal("existing CRUD CLI not applied")
	}
}
