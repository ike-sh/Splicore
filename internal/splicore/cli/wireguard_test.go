//go:build with_gvisor

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/cli"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/registry/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func TestWireGuardAPITransportCLI(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"), sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p, e, x, _ := testfixture.Foundation()
	service, err := application.New(store, p, e, x, version.Current())
	if err != nil {
		t.Fatal(err)
	}
	defer service.CloseWireGuardEndpoints(ctx)
	server := httptest.NewServer(api.Handler(service))
	defer server.Close()
	control := transport.TestClient(server.Client(), server.URL)
	defer control.Close()
	var stdout, stderr bytes.Buffer
	if code := cli.Run(ctx, []string{"wireguard", "keygen"}, &stdout, &stderr, cli.Dependencies{}); code != 0 {
		t.Fatal(stderr.String())
	}
	var pair struct{ PrivateKey, PublicKey string }
	if json.Unmarshal(stdout.Bytes(), &pair) != nil {
		t.Fatal("bad explicit keygen output")
	}
	if _, err = E.DecodeKey(pair.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err = E.DecodeKey(pair.PublicKey); err != nil {
		t.Fatal(err)
	}
	_, peer, err := application.GenerateWireGuardKeys()
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"tag":"api-wg","addresses":["10.34.0.1/32"],"private_key":"` + pair.PrivateKey + `","listen_port":0,"peers":[{"public_key":"` + peer + `","allowed_ips":["10.34.0.2/32"]}]}`
	file := filepath.Join(t.TempDir(), "endpoint.json")
	if err = os.WriteFile(file, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		stdout.Reset()
		stderr.Reset()
		if code := cli.Run(ctx, append([]string{"wireguard"}, args...), &stdout, &stderr, cli.Dependencies{Queries: control}); code != 0 {
			t.Fatal(args, stderr.String())
		}
		if strings.Contains(stdout.String(), pair.PrivateKey) || strings.Contains(stderr.String(), pair.PrivateKey) {
			t.Fatal("normal control response leaked private key")
		}
	}
	run("validate", "--file", file)
	run("create", "--file", file)
	run("start", "--tag", "api-wg")
	run("status", "--tag", "api-wg")
	if !strings.Contains(stdout.String(), `"ACTIVE"`) {
		t.Fatal("not active")
	}
	run("list")
	run("replace", "--file", file)
	run("close", "--tag", "api-wg")
	run("close", "--tag", "api-wg")
	var config E.WireGuard
	if err = json.Unmarshal([]byte(raw), &config); err != nil {
		t.Fatal(err)
	}
	if err = control.ValidateWireGuardEndpoint(ctx, config); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, body string
		code               int
	}{
		{"PUT", "", raw, 405}, {"GET", "/validate", "", 405}, {"GET", "?token=secret", "", 400}, {"POST", "/validate", strings.Replace(raw, "api-wg", "validate", 1), 400}, {"POST", "/validate", strings.Replace(raw, `"listen_port":0`, `"unknown":"secret","listen_port":0`, 1), 400}, {"POST", "/validate", strings.Replace(raw, pair.PrivateKey, "secret-bad-base64", 1), 400}, {"POST", "/api-wg/start", `{"private_key":"secret"}`, 400}, {"POST", "/api-wg/replace", strings.Replace(raw, "api-wg", "other", 1), 400}, {"GET", "/api-wg/unknown", "", 404}, {"POST", "/validate", strings.Repeat("x", application.ClientDocumentLimit+1), 400},
	} {
		request, err := http.NewRequest(tc.method, server.URL+"/api/v1/wireguard/endpoints"+tc.path, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		_, _ = body.ReadFrom(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != tc.code {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, response.StatusCode, body.String())
		}
		if strings.Contains(body.String(), "secret") || strings.Contains(body.String(), pair.PrivateKey) {
			t.Fatal("error leaked request secret")
		}
	}
}
