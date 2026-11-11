package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/cli"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func capturePublicCapabilities(t *testing.T, name string, value any) {
	t.Helper()
	root := os.Getenv("SPLICORE_V021_FIX_CAPTURE_DIR")
	if root == "" {
		return
	}
	if !filepath.IsAbs(root) {
		t.Fatal("capture directory must be absolute")
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, name+".json"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

// Check values actually returned to users, including future metadata additions.
// Historical comments and internal documentation are outside this test's scope.
func assertPublicCapabilityStrings(t *testing.T, data []byte) {
	t.Helper()
	internal := regexp.MustCompile(`(?i)docs/reports/|phase[^\s"/]*report|review[_ -]?report|freeze[_ -]?report|splicore-validation|[DC]:/(?:code/|Users/)|docs/architecture/(?:TROJAN|VMESS)_RUNTIME\.md`)
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal("public response is not JSON", err)
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if internal.MatchString(strings.ReplaceAll(x, `\`, "/")) {
				t.Errorf("internal engineering reference in public response: %q", x)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		case map[string]any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(value)
}

func TestPublicCapabilitiesPublicMetadata(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"), sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	p, e, x, err := registry.NativeCore()
	if err != nil {
		t.Fatal(err)
	}
	service, err := application.New(store, p, e, x, version.Current())
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.Capabilities(ctx, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	capturePublicCapabilities(t, "service", page)
	counts := map[string]int{}
	snellVersions := map[string]bool{}
	for _, item := range page.Items {
		if item.Protocol == "snell" {
			snellVersions[item.WireVersion] = true
			if item.WireVersion == "4" && (len(item.QualifiedClients) != 2 || !item.Roles.Inbound || !item.Roles.Outbound || !item.Features.TCP || !item.Features.UDPPayload) {
				t.Fatal("explicit v4 capability incomplete", item)
			}
		}
		counts[item.Protocol] += len(item.QualifiedClients)
		for _, client := range item.QualifiedClients {
			if client.Client == "" || client.Evidence != "" {
				t.Errorf("%s: compatibility identity or empty public evidence contract violated: %+v", item.Protocol, client)
			}
		}
	}
	if len(snellVersions) != 3 || !snellVersions["4"] || !snellVersions["5"] || !snellVersions["6"] {
		t.Fatal("Snell version capability missing", snellVersions)
	}
	for group, want := range map[string]int{"hysteria2": 2, "tuic": 2, "mieru": 2, "snell": 5, "trojan": 3, "vmess": 3} {
		if counts[group] != want {
			t.Errorf("%s: qualified client membership changed: got %d, want %d", group, counts[group], want)
		}
	}
	data, _ := json.Marshal(page)
	assertPublicCapabilityStrings(t, data)

	handler := api.Handler(service)
	var items []application.Capability
	cursor := ""
	for requests := 0; ; requests++ {
		if requests > len(page.Items) {
			t.Fatal("capability pagination did not terminate")
		}
		request := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities?limit=1", nil)
		query := request.URL.Query()
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		request.URL.RawQuery = query.Encode()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("capability API response failed", response.Code)
		}
		assertPublicCapabilityStrings(t, response.Body.Bytes())
		var wire map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &wire); err != nil {
			t.Fatal(err)
		}
		for _, raw := range wire["items"].([]any) {
			clients, ok := raw.(map[string]any)["qualified_clients"].([]any)
			if !ok {
				t.Fatal("qualified_clients must remain an array, including when empty")
			}
			for _, value := range clients {
				client := value.(map[string]any)
				if len(client) != 3 {
					t.Fatal("qualified client JSON shape changed")
				}
				for _, key := range []string{"client", "version", "evidence"} {
					if _, ok := client[key].(string); !ok {
						t.Fatal("required qualified client string missing", key)
					}
				}
			}
		}
		var next application.CapabilityPage
		if err := json.Unmarshal(response.Body.Bytes(), &next); err != nil {
			t.Fatal(err)
		}
		items = append(items, next.Items...)
		cursor = next.NextCursor
		if cursor == "" {
			break
		}
	}
	actualItems, _ := json.Marshal(items)
	expectedItems, _ := json.Marshal(page.Items)
	if !bytes.Equal(actualItems, expectedItems) {
		t.Fatal("paginated API differs from application capabilities")
	}
	capturePublicCapabilities(t, "api", application.CapabilityPage{Items: items, SnapshotRevision: page.SnapshotRevision})

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := transport.TestClient(server.Client(), server.URL)
	t.Cleanup(client.Close)
	var stdout, stderr bytes.Buffer
	if code := cli.Run(ctx, []string{"capabilities"}, &stdout, &stderr, cli.Dependencies{Build: version.Current(), Queries: client}); code != 0 {
		t.Fatal("CLI capabilities failed", code, stderr.String())
	}
	assertPublicCapabilityStrings(t, stdout.Bytes())
	var output application.CapabilityPage
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal("CLI capabilities are not JSON", err)
	}
	actualPage, _ := json.Marshal(output)
	if !bytes.Equal(actualPage, data) {
		t.Fatal("CLI capabilities do not preserve the service/API JSON contract")
	}
	capturePublicCapabilities(t, "cli", output)
}

func TestPublicCapabilityEvidenceSchemaAllowsEmptyString(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "..", "docs", "api", "openapi-skeleton.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	components := schema["components"].(map[string]any)["schemas"].(map[string]any)
	capability := components["Capability"].(map[string]any)["properties"].(map[string]any)
	item := capability["qualified_clients"].(map[string]any)["items"].(map[string]any)
	evidence := item["properties"].(map[string]any)["evidence"].(map[string]any)
	if evidence["type"] != "string" || evidence["minLength"] != nil || evidence["pattern"] != nil || evidence["format"] != nil {
		t.Fatal("evidence schema must admit the preserved empty string representation")
	}
	found := false
	for _, name := range item["required"].([]any) {
		found = found || name == "evidence"
	}
	if !found {
		t.Fatal("evidence field must remain required in each compatibility record")
	}
}
