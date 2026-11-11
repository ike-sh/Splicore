package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig(t *testing.T) string {
	path := filepath.ToSlash(t.TempDir())
	return fmt.Sprintf("schema: 1\nstate_directory: '%s'\napi:\n  unix_socket: '%s/control.sock'\n", path, path)
}

func TestStrictBootstrap(t *testing.T) {
	s := validConfig(t)
	if _, err := Decode(strings.NewReader(s)); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{s + "accounts: []\n", s + "schema: 1\n", strings.ReplaceAll(s, "schema: 1", "schema: 2"), s + "---\n" + s, strings.ReplaceAll(s, "api:", "api: &alias"), strings.Repeat("x", MaxBytes+1), "schema: 1\nstate_directory: relative\napi: {}"} {
		if _, err := Decode(strings.NewReader(s)); err == nil {
			t.Fatal("invalid bootstrap accepted")
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("schema: 1\nstate_directory: /tmp/splicore-fixture\napi:\n  unix_socket: /tmp/splicore-fixture/control.sock\n")
	f.Add("accounts: []")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := Decode(strings.NewReader(s))
		if err == nil && c.Validate() != nil {
			t.Fatal("decoder accepted invalid config")
		}
	})
}
