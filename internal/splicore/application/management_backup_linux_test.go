package application_test

import (
	"bytes"
	"context"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/nodeimport"
	"github.com/sagernet/sing-box/internal/splicore/storage/sqlite"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPhase14BackupRestoreOffline(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "original", "state.db")
	s, store := setupSnell(t, path, nil)
	enableClient(t, s)
	closed := false
	defer func() {
		if !closed {
			stop(t, s, store)
		}
	}()
	remote := freePort(t)
	created := apply(t, s, doc(remote, 6))
	psk := remotePSK(t, store, created.InboundID)
	feed := &managementFeed{}
	feed.set(feedDocument([]nodeimport.Candidate{snellCandidate("original", access.Endpoint{Host: "127.0.0.1", Port: remote}, psk)}), "PRIVATE_VALIDATOR", 0)
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "backup-provider", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: fixture.URL + "?secret=PRIVATE_SOURCE", Auth: &provider.Auth{Type: "bearer", Value: "PRIVATE_AUTH"}}})
	if _, e := s.RefreshProvider(ctx, p.ProviderID); e != nil {
		t.Fatal(e)
	}
	node := providerNodes(t, s, p.ProviderID)[0]
	managementApply(t, s, application.ManagementRequest{Operation: "batch", Action: "tag", IDs: []identity.ID{node.ID}, Tags: []string{"restored-tag"}})
	rules := &managementFeed{}
	rules.set(`{"schema_version":1,"rules":[{"domain_suffixes":["example.test"]}]}`, "", 0)
	rulesFixture := httptest.NewServer(http.HandlerFunc(rules.serve))
	defer rulesFixture.Close()
	rp := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "backup-rules", Kind: "ruleset", Format: "canonical-rules", AllowPrivate: true}, Source: &provider.Source{URL: rulesFixture.URL}})
	if _, e := s.RefreshProvider(ctx, rp.ProviderID); e != nil {
		t.Fatal(e)
	}
	before, e := s.ClientStatus(ctx)
	if e != nil {
		t.Fatal(e)
	}
	oid := before.State.Outbounds[1].ID
	local := freePort(t)
	addLocal(t, s, local, oid)
	before, _ = s.ClientStatus(ctx)
	target := echoTarget(t, "127.0.0.1")
	if e = transfer(local, target, []byte("before-backup")); e != nil {
		t.Fatal(e)
	}
	waitIdle(t, s)
	stop(t, s, store)
	closed = true
	fixture.Close()
	rulesFixture.Close()
	backup := filepath.Join(root, "snapshot", "state.db")
	schema, e := sqlite.MaintenanceBackup(ctx, path, backup)
	if e != nil || schema != 8 {
		t.Fatal("SQLite backup", schema, e)
	}
	raw, e := os.ReadFile(backup)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{psk, "PRIVATE_VALIDATOR", "PRIVATE_SOURCE", "PRIVATE_AUTH"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("plaintext source or credential at rest")
		}
	}
	restored, restoredStore := setupSnell(t, backup, nil)
	enableClient(t, restored)
	defer stop(t, restored, restoredStore)
	after, e := restored.ClientStatus(ctx)
	if e != nil || !reflect.DeepEqual(before.State, after.State) {
		t.Fatal("restored canonical authority", e)
	}
	if e = transfer(local, target, []byte("offline-restored-traffic")); e != nil {
		t.Fatal(e)
	}
	waitIdle(t, restored)
}
