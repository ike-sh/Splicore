//go:build with_quic && with_utls

package application_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/operations"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func TestPhase19VMessBackupRestore(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "original", "state.db")
	s, store := setupProtocols(t, path, nil, registry.NativeCore)
	enableVMess(t, s)
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
	for _, method := range []string{"VMess-primary", "VMess-secondary"} {
		created := vmessCreation(t, s)
		ids = append(ids, created.InboundID)
		for user := range created.Bindings {
			c := vmessCandidate(t, s, created, user)
			c.Key = method + c.Key
			c.Node.Name = c.Key
			ssImportedOutbound(t, s, c)
			secrets = append(secrets, c.Credential.Value)
			if providerID == "" && method == "VMess-secondary" {
				feed.set(feedDocument([]nodeimport.Candidate{c}), "", 0)
				p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "VMess backup provider", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: fixture.URL}})
				providerID = p.ProviderID
				if _, e := s.RefreshProvider(ctx, providerID); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	before, _ := s.ClientStatus(ctx)
	serverBefore, _ := s.Inbounds(ctx)
	bundle := filepath.Join(root, "support", "bundle.tar.gz")
	cfg := config.Config{Schema: 1, StateDirectory: filepath.Dir(path), API: config.API{UnixSocket: filepath.Join(root, "control.sock")}}
	if e := operations.SupportBundle(ctx, cfg, version.Current(), s, bundle); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(bundle)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		raw, e := io.ReadAll(tr)
		if e != nil {
			t.Fatal(e)
		}
		for _, password := range secrets {
			digest := sha256.Sum256([]byte(password))
			command := vm.CommandKey(access.UUIDPayload{UUID: secret.New(password)})
			if bytes.Contains(raw, []byte(hex.EncodeToString(command[:]))) {
				t.Fatal("support leaked VMess command key")
			}
			if bytes.Contains(raw, []byte(password)) || bytes.Contains(raw, []byte(hex.EncodeToString(digest[:]))) {
				t.Fatal("support leaked password or digest")
			}
		}
		if bytes.Contains(raw, []byte("BEGIN PRIVATE KEY")) {
			t.Fatal("support leaked private key")
		}
		if h.Name == "listeners.json" && !bytes.Contains(raw, []byte(`"vmess"`)) {
			t.Fatal("support omitted VMess identity")
		}
	}
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
	enableVMess(t, restored)
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
			if _, e = restored.ExportClient(ctx, id, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.2", BindingID: b.BindingID}); e != nil {
				t.Fatal("restored encrypted credential", e)
			}
		}
	}
}
