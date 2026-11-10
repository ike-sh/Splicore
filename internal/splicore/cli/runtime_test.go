package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func TestOfflineRuntimeCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"help", "run"}, {"run", "--help"}, {"version"}, {"version", "--json"}} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), args, &out, &errOut, Dependencies{Build: version.Current()}); code != 0 || out.Len() == 0 || errOut.Len() != 0 {
			t.Fatalf("offline command %v: exit=%d out=%q err=%q", args, code, &out, &errOut)
		}
	}
	var out, errOut bytes.Buffer
	if Run(context.Background(), []string{"help", "unknown"}, &out, &errOut, Dependencies{}) != 1 {
		t.Fatal("unknown help topic accepted")
	}
}

func TestCheckRejectsInvalidAndNeverServes(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "bootstrap.yaml")
	content := "schema: 1\nstate_directory: " + filepath.ToSlash(filepath.Join(dir, "state")) + "\napi:\n  unix_socket: " + filepath.ToSlash(filepath.Join(dir, "control.sock")) + "\n"
	if err := os.WriteFile(valid, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"check", "--config", valid}, {"check", valid}} {
		var out, errOut bytes.Buffer
		if Run(context.Background(), args, &out, &errOut, Dependencies{}) != 0 {
			t.Fatal(errOut.String())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
		t.Fatal("check created state")
	}
	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("schema: 999\nstate_directory: relative\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"check"}, {"check", invalid}, {"check", valid, "unexpected"}, {"run"}, {"check", "--config", valid, "--protocol", "vless"}} {
		var out, errOut bytes.Buffer
		if Run(context.Background(), args, &out, &errOut, Dependencies{}) != 1 || errOut.Len() == 0 {
			t.Fatalf("accepted invalid command %v", args)
		}
	}
	var out, errOut bytes.Buffer
	Run(context.Background(), []string{"check", invalid}, &out, &errOut, Dependencies{})
	if !strings.Contains(errOut.String(), "unsupported bootstrap schema") {
		t.Fatal("missing actionable schema diagnosis:", errOut.String())
	}
}
