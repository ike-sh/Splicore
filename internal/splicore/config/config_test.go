package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapStrictConfiguration(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir())
	base := "schema: 1\nstate_directory: " + dir + "/state\napi:\n  unix_socket: " + dir + "/ctl/core.sock\n"
	if _, err := Decode(strings.NewReader(base)); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"unknown":   base + "amneziawg_endpoints: []\n",
		"duplicate": base + "schema: 1\n",
		"multiple":  base + "---\nschema: 1\n",
		"relative":  strings.Replace(base, dir+"/state", "relative", 1),
		"missing":   "schema: 1\n",
		"schema":    strings.Replace(base, "schema: 1", "schema: 999", 1),
		"alias":     base + "key_file: &key /key\nextra: *key\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(content)); err == nil {
				t.Fatal("invalid bootstrap accepted")
			}
		})
	}
}
