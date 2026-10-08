package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/cli"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestPhase20AuthRESTCLIAndBindingCleanup(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableProxyInterfaces(t, s)
	i, bid := createProxyListener(t, s, "mixed", true)
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	ctl := transport.TestClient(server.Client(), server.URL)
	defer ctl.Close()
	call := func(method, path string, body any) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, server.URL+"/api/v1/"+path, bytes.NewReader(raw))
		state, _ := s.ClientStatus(ctx)
		req.Header.Set("If-Match", fmt.Sprintf(`"%d"`, state.State.Revision))
		resp, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatal("REST", method, path, resp.StatusCode, string(b))
		}
		if bytes.Contains(b, []byte("fixture")) {
			t.Fatal("REST returned credential")
		}
		return b
	}
	raw := call("GET", "local-bindings/"+string(bid), nil)
	var binding access.Binding
	if json.Unmarshal(raw, &binding) != nil || binding.InboundID != i.ID {
		t.Fatal("generic binding lookup")
	}
	oldCredential := binding.CredentialID
	call("POST", "local-bindings/"+string(bid)+"/credential", map[string]any{"credential": proxyAuthInput("rotated-fixture")})
	if _, e := store.RevealCredential(ctx, oldCredential); e == nil {
		t.Fatal("rotated exclusive credential retained")
	}
	echo := phase20Echo(t)
	phase20Stream(t, i, echo, "rotated-fixture")
	i.Kind = "http"
	phase20Stream(t, i, echo, "rotated-fixture")
	var out, errOut bytes.Buffer
	deps := cli.Dependencies{Queries: ctl, Build: version.Current()}
	for _, args := range [][]string{{"local-binding", "list"}, {"local-binding", "get", "--id", string(bid)}, {"client", "status"}, {"doctor"}} {
		out.Reset()
		errOut.Reset()
		if cli.Run(ctx, args, &out, &errOut, deps) != 0 {
			t.Fatal("CLI", errOut.String())
		}
		if bytes.Contains(out.Bytes(), []byte("rotated-fixture")) {
			t.Fatal("CLI credential leak")
		}
	}
	raw = call("GET", "local-bindings/"+string(bid), nil)
	_ = json.Unmarshal(raw, &binding)
	binding.Enabled = false
	call("PUT", "local-bindings/"+string(bid), map[string]any{"binding": binding})
	call("DELETE", "local-bindings/"+string(bid), nil)
	if _, e := store.RevealCredential(ctx, binding.CredentialID); e == nil {
		t.Fatal("deleted exclusive credential retained")
	}
}
func TestPhase20ProxyProviderFailurePreservesGeneration(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableProxyInterfaces(t, s)
	c, e := nodeimport.ParseURI("socks5h://synthetic:fixture@127.0.0.1:1#provider")
	if e != nil {
		t.Fatal(e)
	}
	c.Key = "socks-proxy"
	feed := &managementFeed{}
	feed.set(feedDocument([]nodeimport.Candidate{c}), "", 0)
	server := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer server.Close()
	preview := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "proxy provider", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: server.URL}})
	if _, e = s.RefreshProvider(ctx, preview.ProviderID); e != nil {
		t.Fatal(e)
	}
	before, _ := s.ClientStatus(ctx)
	c.Node.Protocol.Protocol = "http"
	c.Node.Options.Data = []byte(`{"auth":true,"udp":true}`)
	feed.set(feedDocument([]nodeimport.Candidate{c}), "", 0)
	if _, e = s.RefreshProvider(ctx, preview.ProviderID); e == nil {
		t.Fatal("provider accepted HTTP UDP")
	}
	after, _ := s.ClientStatus(ctx)
	if !reflect.DeepEqual(before.State.Nodes, after.State.Nodes) || !reflect.DeepEqual(before.State.Outbounds, after.State.Outbounds) {
		t.Fatal("failed refresh changed committed node generation")
	}
}
func TestPhase20ProxyBackupRestore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("maintenance backup is Linux scoped")
	}
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "original", "state.db")
	s, store := setupProtocols(t, path, nil, registry.NativeCore)
	enableProxyInterfaces(t, s)
	closed := false
	defer func() {
		if !closed {
			stop(t, s, store)
		}
	}()
	i, bid := createProxyListener(t, s, "mixed", true)
	for _, scheme := range []string{"socks5h", "http"} {
		c, e := nodeimport.ParseURI(scheme + "://synthetic:backup-fixture@127.0.0.1:1#backup-proxy")
		if e != nil {
			t.Fatal(e)
		}
		clientApply(t, s, application.ClientMutation{Resource: "node", Action: "create", Node: &c.Node, Credential: &application.CredentialInput{Kind: c.Credential.Kind, Value: c.Credential.Value}})
	}
	before, e := s.ClientStatus(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var binding access.Binding
	for _, local := range before.State.LocalInbounds {
		if local.ID == i.ID {
			binding = local.Bindings[0]
		}
	}
	accountBefore, e := store.Account(ctx, binding.AccountID)
	if e != nil {
		t.Fatal(e)
	}
	stop(t, s, store)
	closed = true
	backup := filepath.Join(root, "backup", "state.db")
	schema, e := sqlite.MaintenanceBackup(ctx, path, backup)
	if e != nil || schema != 8 {
		t.Fatal("backup", schema, e)
	}
	raw, e := os.ReadFile(backup)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("backup-fixture")) || bytes.Contains(raw, []byte(`"username":"synthetic"`)) {
		t.Fatal("SQLite plaintext credential")
	}
	restored, rs := setupProtocols(t, backup, nil, registry.NativeCore)
	defer stop(t, restored, rs)
	enableProxyInterfaces(t, restored)
	after, e := restored.ClientStatus(ctx)
	if e != nil || !reflect.DeepEqual(before.State, after.State) {
		t.Fatal("stable IDs/auth settings did not roundtrip", e)
	}
	a, e := rs.Account(ctx, binding.AccountID)
	if e != nil || !reflect.DeepEqual(a, accountBefore) {
		t.Fatal("account roundtrip", e)
	}
	cred, e := rs.RevealCredential(ctx, binding.CredentialID)
	if e != nil || cred.Kind != access.UsernamePassword || bid != binding.ID {
		t.Fatal("encrypted binding roundtrip", e)
	}
	phase20Stream(t, i, phase20Echo(t), "fixture")
}
