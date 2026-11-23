package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
)

func TestLegacyWitnessUpgradeDiagnosticSurvivesCLIRedaction(t *testing.T) {
	var stderr bytes.Buffer
	if exit := failure(&stderr, identity.Err(identity.Invalid, identity.LegacyWitnessRequiredMessage)); exit == 0 || !strings.Contains(stderr.String(), "state establish-witness --acknowledge-current-state") {
		t.Fatal("fixed upgrade guidance was redacted", exit, stderr.String())
	}
}

func TestStateWitnessOperations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "state.db")
	store, err := sqlite.Open(ctx, path, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, map[string]any, string) {
		var out, stderr bytes.Buffer
		exit := Run(ctx, args, &out, &stderr, Dependencies{})
		decoded := map[string]any{}
		if out.Len() > 0 {
			if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
				t.Fatal(err, out.String())
			}
		}
		return exit, decoded, stderr.String()
	}
	if exit, result, stderr := run("state", "integrity", "--source", path); exit != 0 || result["status"] != "verified" || stderr != "" {
		t.Fatal(exit, result, stderr)
	}
	if err = os.Remove(path + ".witness"); err != nil {
		t.Fatal(err)
	}
	if exit, _, stderr := run("state", "establish-witness", "--source", path); exit == 0 || stderr == "" {
		t.Fatal("implicit witness establishment accepted", exit, stderr)
	}
	if exit, result, stderr := run("state", "establish-witness", "--source", path, "--acknowledge-current-state"); exit != 0 || result["status"] != "verified" || result["lineage"] != "legacy_baseline" || stderr != "" {
		t.Fatal(exit, result, stderr)
	}
}
