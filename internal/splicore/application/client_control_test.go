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
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientRESTCRUDRevisionSecurityAndCLI(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, store := setupSnell(t, filepath.Join(dir, "state", "state.db"), nil)
	defer stop(t, s, store)
	enableClient(t, s)
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	ctl := transport.TestClient(server.Client(), server.URL)
	defer ctl.Close()
	call := func(method, path string, body any, expected int) []byte {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(b))
		if method != http.MethodGet {
			st, _ := s.ClientStatus(ctx)
			req.Header.Set("If-Match", fmt.Sprintf(`"%d"`, st.State.Revision))
		}
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != expected {
			t.Fatal(method, path, res.StatusCode, string(raw))
		}
		if strings.Contains(string(raw), "SyntheticControlPSK123456") {
			t.Fatal("secret in generic response")
		}
		return raw
	}
	nodeDoc := client.RemoteNode{Name: "REST node", Protocol: snell.Key(5), Endpoint: access.Endpoint{Host: "localhost", Port: 12345}, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: []byte(`{"version":5}`)}}
	raw := call("POST", "/api/v1/nodes", map[string]any{"node": nodeDoc, "credential": application.CredentialInput{Kind: access.PSK, Value: "SyntheticControlPSK123456"}}, 200)
	var result application.ClientResult
	_ = json.Unmarshal(raw, &result)
	nodeID := result.ID
	call("GET", "/api/v1/nodes", nil, 200)
	call("PATCH", "/api/v1/nodes", nil, 405)
	call("GET", "/api/v1/client/runtime/unknown", nil, 404)
	call("DELETE", "/api/v1/client/runtime", nil, 405)
	raw = call("GET", "/api/v1/nodes/"+string(nodeID), nil, 200)
	_ = json.Unmarshal(raw, &nodeDoc)
	nodeDoc.Name = "renamed"
	call("PUT", "/api/v1/nodes/"+string(nodeID), map[string]any{"node": nodeDoc}, 200)
	raw = call("POST", "/api/v1/outbounds", map[string]any{"outbound": client.Outbound{Name: "REST outbound", Kind: "proxy", NodeID: &nodeID, Engine: "native"}}, 200)
	_ = json.Unmarshal(raw, &result)
	outID := result.ID
	call("PUT", "/api/v1/client/route", map[string]any{"route": client.Route{DefaultOutbound: outID}}, 200)
	call("DELETE", "/api/v1/nodes/"+string(nodeID), map[string]any{}, 400)
	call("DELETE", "/api/v1/outbounds/"+string(outID), map[string]any{}, 400)
	raw = call("POST", "/api/v1/local-inbounds", map[string]any{"local_inbound": client.LocalInbound{Name: "REST local", Listen: access.Endpoint{Port: freePort(t)}}}, 200)
	_ = json.Unmarshal(raw, &result)
	localID := result.ID
	call("GET", "/api/v1/local-inbounds/"+string(localID), nil, 200)
	call("GET", "/api/v1/outbounds/"+string(outID), nil, 200)
	call("GET", "/api/v1/client/route", nil, 200)
	call("POST", "/api/v1/nodes/"+string(nodeID)+"/credential", map[string]any{"credential": application.CredentialInput{Kind: access.PSK, Value: "short"}}, 400)
	call("POST", "/api/v1/nodes/"+string(nodeID)+"/credential", map[string]any{"credential": application.CredentialInput{Kind: access.PSK, Value: "SyntheticControlPSK123456"}}, 200)
	call("POST", "/api/v1/outbounds", map[string]any{"outbound": client.Outbound{Name: "unsupported", Kind: "proxy", NodeID: &nodeID, Engine: "xray"}}, 422)
	call("POST", "/api/v1/client/plan", map[string]any{"resource": "runtime", "action": "start", "unknown": true}, 400)
	stale, _ := http.NewRequest("PUT", server.URL+"/api/v1/client/route", strings.NewReader(`{"route":{"default_outbound":"direct"}}`))
	stale.Header.Set("If-Match", `"0"`)
	res, e := server.Client().Do(stale)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 409 {
		t.Fatal("stale revision accepted")
	}
	var stdout, stderr bytes.Buffer
	deps := cli.Dependencies{Queries: ctl, Build: version.Current()}
	for _, args := range [][]string{{"status"}, {"doctor"}, {"client", "status"}, {"node", "list"}, {"node", "get", "--id", string(nodeID)}, {"outbound", "list"}, {"local-inbound", "list"}, {"route", "get"}} {
		stdout.Reset()
		stderr.Reset()
		if cli.Run(ctx, args, &stdout, &stderr, deps) != 0 {
			t.Fatal(args, stderr.String())
		}
		if strings.Contains(stdout.String(), "SyntheticControlPSK123456") {
			t.Fatal("CLI leak")
		}
		if args[0] == "status" && !strings.Contains(stdout.String(), "client_runtime") {
			t.Fatal("client missing from unified status")
		}
		if args[0] == "doctor" && !strings.Contains(stdout.String(), "local_listeners") {
			t.Fatal("doctor missing client state")
		}
	}
	mutation := application.ClientMutation{Resource: "route", Action: "update", Route: &client.Route{DefaultOutbound: client.Direct}}
	b, _ := json.Marshal(mutation)
	file := filepath.Join(dir, "route.json")
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if cli.Run(ctx, []string{"route", "plan", "--file", file}, &stdout, &stderr, deps) != 0 {
		t.Fatal(stderr.String())
	}
	var p ports.ClientPlan
	if json.Unmarshal(stdout.Bytes(), &p) != nil {
		t.Fatal("plan output")
	}
	saved := filepath.Join(dir, "plan.json")
	os.WriteFile(saved, stdout.Bytes(), 0600)
	stdout.Reset()
	if cli.Run(ctx, []string{"route", "apply", "--file", file, "--plan", saved}, &stdout, &stderr, deps) != 0 {
		t.Fatal(stderr.String())
	}
	for _, action := range []string{"stop", "start", "restart"} {
		stdout.Reset()
		if cli.Run(ctx, []string{"client", action}, &stdout, &stderr, deps) != 0 {
			t.Fatal(action, stderr.String())
		}
	}
	call("DELETE", "/api/v1/local-inbounds/"+string(localID), map[string]any{}, 200)
	call("DELETE", "/api/v1/outbounds/"+string(outID), map[string]any{}, 200)
	call("DELETE", "/api/v1/nodes/"+string(nodeID), map[string]any{}, 200)
	call("GET", "/api/v1/nodes/"+string(nodeID), nil, 404)
}
