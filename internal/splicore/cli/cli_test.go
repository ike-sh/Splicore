package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/registry/testfixture"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/cli"
	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func TestCLIAndAPIShareSystem(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"), sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p, e, x, _ := testfixture.Foundation()
	service, _ := application.New(store, p, e, x, version.Current())
	server := httptest.NewServer(api.Handler(service))
	defer server.Close()
	client := transport.TestClient(server.Client(), server.URL)
	defer client.Close()
	var stdout, stderr bytes.Buffer
	if cli.Run(ctx, []string{"status"}, &stdout, &stderr, cli.Dependencies{Build: version.Current(), Queries: client}) != 0 {
		t.Fatal(stderr.String())
	}
	var got application.System
	if json.Unmarshal(stdout.Bytes(), &got) != nil {
		t.Fatal("status not canonical response")
	}
	want, _ := service.System(ctx)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("CLI status differs from application System")
	}
	response, err := http.Get(server.URL + "/api/v1/system")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var wire application.System
	if json.NewDecoder(response.Body).Decode(&wire) != nil || !reflect.DeepEqual(got, wire) {
		t.Fatal("CLI and HTTP paths diverged")
	}
	for _, command := range []string{"doctor", "capabilities", "version"} {
		stdout.Reset()
		stderr.Reset()
		if cli.Run(ctx, []string{command}, &stdout, &stderr, cli.Dependencies{Build: version.Current(), Queries: client}) != 0 {
			t.Fatal(stderr.String())
		}
		if strings.Contains(stdout.String(), "dummy-password") {
			t.Fatal("diagnostic secret leak")
		}
	}
}

func TestOfflineAndBootstrapCommands(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer
	client := transport.UnixClient(filepath.Join(t.TempDir(), "missing.sock"))
	defer client.Close()
	if cli.Run(ctx, []string{"status"}, &stdout, &stderr, cli.Dependencies{Queries: client}) != 0 || stdout.String() != "not running\n" {
		t.Fatal("absent daemon not normal", stderr.String())
	}
	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	c := config.Config{Schema: 1, StateDirectory: t.TempDir(), API: config.API{UnixSocket: filepath.Join(t.TempDir(), "control.sock")}}
	b, _ := json.Marshal(c)
	if os.WriteFile(path, b, 0o600) != nil {
		t.Fatal("fixture write")
	}
	stdout.Reset()
	if cli.Run(ctx, []string{"validate", path}, &stdout, &stderr, cli.Dependencies{}) != 0 {
		t.Fatal(stderr.String())
	}
	for _, args := range [][]string{{"validate"}, {"version", "unexpected"}, {"unknown"}, {"run"}, {"status", "--bad"}} {
		if cli.Run(ctx, args, &stdout, &stderr, cli.Dependencies{}) == 0 {
			t.Fatal("invalid invocation accepted")
		}
	}
}
