//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
)

func TestPhase16ShadowsocksBackupRestore(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "original", "state.db")
	s, store := setupProtocols(t, path, nil, registry.NativeCore)
	enableSS(t, s)
	closed := false
	defer func() {
		if !closed {
			stop(t, s, store)
		}
	}()
	var ids []identity.ID
	var secrets []string
	feed := &managementFeed{}
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	var providerID identity.ID
	for _, method := range []string{"aes-256-gcm", "2022-blake3-aes-256-gcm"} {
		created := ssCreation(t, s, method, method != "aes-256-gcm")
		ids = append(ids, created.InboundID)
		for user := range created.Bindings {
			c := ssCandidate(t, s, created, user)
			c.Key = method + c.Key
			c.Node.Name = c.Key
			ssImportedOutbound(t, s, c)
			secrets = append(secrets, c.Credential.Value)
			if providerID == "" && method == "2022-blake3-aes-256-gcm" {
				feed.set(feedDocument([]nodeimport.Candidate{c}), "", 0)
				p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "SS backup provider", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: fixture.URL}})
				providerID = p.ProviderID
				if _, e := s.RefreshProvider(ctx, providerID); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	before, _ := s.ClientStatus(ctx)
	serverBefore, _ := s.Inbounds(ctx)
	stop(t, s, store)
	closed = true
	backup := filepath.Join(root, "backup", "state.db")
	schema, e := sqlite.MaintenanceBackup(ctx, path, backup)
	if e != nil || schema != 8 {
		t.Fatal(schema, e)
	}
	raw, e := os.ReadFile(backup)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range secrets {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("plaintext SQLite credential")
		}
	}
	restored, rs := setupProtocols(t, backup, nil, registry.NativeCore)
	defer stop(t, restored, rs)
	enableSS(t, restored)
	after, _ := restored.ClientStatus(ctx)
	if !reflect.DeepEqual(before.State, after.State) {
		t.Fatal("backup changed stable node/outbound/reference IDs")
	}
	serverAfter, _ := restored.Inbounds(ctx)
	if _, e = restored.RefreshProvider(ctx, providerID); e != nil {
		t.Fatal("restored encrypted provider source", e)
	}
	if !reflect.DeepEqual(serverBefore, serverAfter) {
		t.Fatal("backup changed server account/binding/inbound state")
	}
	for _, id := range ids {
		view, _ := restored.Inbound(ctx, id)
		for _, b := range view.Bindings {
			if _, e = restored.ExportClient(ctx, id, application.ExportRequest{Format: ports.URI, BindingID: b.BindingID}); e != nil {
				t.Fatal("restored encrypted credential", e)
			}
		}
	}
}
