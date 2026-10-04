package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/api"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/cli"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

// Desired-state/control testing deliberately never creates an OS device or
// touches the development host's routes, DNS, registry proxy or drivers.
func TestHostIntegrationProtectedControlAndStoppedDesiredTUN(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s, store := setupSnell(t, filepath.Join(root, "state", "state.db"), nil)
	defer stop(t, s, store)
	factories, err := registry.NewOutbounds()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(ctx, factories, filepath.Join(root, "host-network")); err != nil {
		t.Fatal(err)
	}
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	call := func(method, path string, body any, revision bool, want int) []byte {
		t.Helper()
		b, _ := json.Marshal(body)
		r, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(b))
		if revision {
			status, e := s.ClientStatus(ctx)
			if e != nil {
				t.Fatal(e)
			}
			r.Header.Set("If-Match", fmt.Sprintf(`"%d"`, status.State.Revision))
		}
		response, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		wire, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("%s %s: %d %s", method, path, response.StatusCode, wire)
		}
		return wire
	}
	call("GET", "/api/v1/client/host-network", nil, false, 200)
	call("GET", "/api/v1/client/host-integration", nil, false, 200)
	call("PUT", "/api/v1/client/host-integration", map[string]any{"host_integration": client.HostIntegration{}}, false, 400)
	call("PUT", "/api/v1/client/host-integration", map[string]any{"host_integration": client.HostIntegration{}}, true, 200)
	call("POST", "/api/v1/client/host-network/repair", map[string]any{"raw_command": "reset-network"}, true, 400)
	call("POST", "/api/v1/client/host-network/repair", map[string]any{}, true, 200)
	inbound := client.LocalInbound{Name: "stopped desired TUN", Kind: "tun", TUN: &client.TUNSettings{Interface: "splicore0", Addresses: []string{"198.18.0.1/30"}, MTU: 1500, Stack: "gvisor"}}
	call("POST", "/api/v1/local-inbounds", map[string]any{"local_inbound": inbound}, true, 200)
	response := call("GET", "/api/v1/local-inbounds", nil, false, 200)
	if strings.Contains(string(response), `"listen"`) {
		t.Fatal("TUN exposed a fabricated listener endpoint")
	}
	ctl := transport.TestClient(server.Client(), server.URL)
	defer ctl.Close()
	for _, command := range [][]string{{"tun", "status"}, {"system-proxy", "status"}, {"doctor"}, {"network", "repair"}} {
		var out, stderr bytes.Buffer
		if cli.Run(ctx, command, &out, &stderr, cli.Dependencies{Queries: ctl, Build: version.Current()}) != 0 {
			t.Fatal(command, stderr.String())
		}
		if command[0] == "doctor" && !strings.Contains(out.String(), "host_network_journal") {
			t.Fatal("doctor omitted journal")
		}
	}
	status, err := s.ClientStatus(ctx)
	if err != nil || status.State.Enabled || status.Host.OwnedInterfaces != 0 || status.Host.OwnedRoutes != 0 {
		t.Fatal("stopped desired state mutated host", err, status.Host)
	}
}
