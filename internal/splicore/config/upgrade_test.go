package config

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRetiredBootstrapOnlyAcceptedDuringUpgrade(t *testing.T) {
	base := validConfig(t)
	path := filepath.Join(t.TempDir(), "absent-xray")
	legacy := base + fmt.Sprintf("xray:\n  binary_path: '%s'\n  runtime_directory: '%s'\n", path, path)
	want, err := Decode(strings.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeForUpgrade(strings.NewReader(legacy))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("upgrade did not preserve native bootstrap", err)
	}
	if _, err := Decode(strings.NewReader(legacy)); err == nil {
		t.Fatal("serve accepted retired runtime configuration")
	}
	for _, section := range []string{
		"xray: []\n", "xray:\n  binary_path: relative\n",
		"xray:\n  unknown: ignored\n", "xray:\n  binary_path: 123\n",
		"xray: {}\nxray: {}\n", "xray: &alias {}\n",
		"xray: {}\nunknown: ignored\n", "---\n" + base,
	} {
		if _, err := DecodeForUpgrade(strings.NewReader(base + section)); err == nil {
			t.Fatal("invalid upgrade bootstrap accepted")
		}
	}
}
