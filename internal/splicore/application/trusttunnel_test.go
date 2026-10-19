//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/cli"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trusttunnel"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/deeplink"
)

func TestTrustTunnelPublicCreationInspectionAndImport(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state/state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	client := transport.TestClient(server.Client(), server.URL)
	defer client.Close()
	for _, mode := range []string{"http2", "http3", "auto"} {
		t.Run(mode, func(t *testing.T) {
			// This is validation/planning metadata; no inbound is applied or bound.
			doc, _ := json.Marshal(map[string]any{"schema": 1, "name": "TrustTunnel plan", "listener": access.Endpoint{Host: "127.0.0.1", Port: 443}, "display_endpoint": access.Endpoint{Host: "vpn.example.test", Port: 443}, "settings": module.Settings{TLS: testkit.TLS(t), Mode: mode}, "users": []any{map[string]any{"account_name": "Alpha", "username": "alpha", "password": "synthetic-password"}}})
			plan, e := client.PlanCreation(ctx, "trusttunnel", doc)
			if e != nil || plan.Protocol != module.Key() || !plan.TLSVerification || plan.Users != 1 {
				t.Fatal(e, plan)
			}
			file := filepath.Join(t.TempDir(), "creation.json")
			if e = os.WriteFile(file, doc, 0600); e != nil {
				t.Fatal(e)
			}
			for _, action := range []string{"validate", "plan"} {
				var out, errOut bytes.Buffer
				if code := cli.Run(ctx, []string{"inbound", action, "--protocol", "trusttunnel", "--file", file}, &out, &errOut, cli.Dependencies{Build: version.Current(), Queries: client}); code != 0 {
					t.Fatal(action, code, errOut.String())
				}
				if bytes.Contains(out.Bytes(), []byte("synthetic-password")) {
					t.Fatal("secret in CLI inspection")
				}
			}
		})
	}
	page, e := client.Capabilities(ctx, "", 200)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, c := range page.Items {
		if c.Protocol == "trusttunnel" {
			found = true
			if !c.Roles.Inbound || !c.Roles.Outbound || !c.Features.TCP || !c.Features.UDPPayload {
				t.Fatal(c)
			}
		}
	}
	if !found {
		t.Fatal("protocol absent from API")
	}
	link, e := deeplink.Encode(deeplink.Link{Hostname: "vpn.example.test", Addresses: []string{"192.0.2.1:443"}, Username: "alpha", Password: "synthetic-password", HasIPv6: true, Protocol: "http3"})
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := nodeimport.Parse("uri", []byte(link))
	if e != nil || len(parsed.Candidates) != 1 || parsed.Candidates[0].Node.Protocol != module.Key() {
		t.Fatal("generic profile import", e)
	}
}
