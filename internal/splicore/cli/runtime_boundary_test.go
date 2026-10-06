package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/cli"
	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func TestRetiredRuntimeCLIActionableAndRedacted(t *testing.T) {
	const message = "retired Xray or transport-mask state retained; remove unsupported records with the previous experimental build before upgrade"
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	c := config.Config{Schema: 1, StateDirectory: t.TempDir(), API: config.API{UnixSocket: filepath.Join(t.TempDir(), "control.sock")}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, want string }{
		{message, "unsupported_engine_for_protocol: " + message + "\n"},
		{"SyntheticPrivateProviderAuth", "unsupported_engine_for_protocol: command rejected\n"},
	} {
		var out, stderr bytes.Buffer
		code := cli.Run(context.Background(), []string{"run", "--config", path}, &out, &stderr, cli.Dependencies{
			Serve: func(context.Context, config.Config) error {
				return identity.Err(identity.UnsupportedEngineForProtocol, tc.input)
			},
		})
		if code != 1 || out.Len() != 0 || stderr.String() != tc.want || strings.Contains(stderr.String(), "SyntheticPrivateProviderAuth") {
			t.Fatal("runtime rejection lacks safe actionable diagnostic")
		}
	}
}
