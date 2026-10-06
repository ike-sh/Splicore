package distribution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/version"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	m := Manifest{Schema: 1, Product: "Splicore", Version: "0.0.0-dev", Channel: "development", Qualification: "experimental", GitCommit: strings.Repeat("a", 40), SourceSHA256: strings.Repeat("b", 64), BuildTime: "2026-10-02T00:00:00Z", GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64", BuildTags: "with_quic,with_utls", ConfigSchema: version.ConfigSchema, DatabaseSchema: version.DatabaseSchema, DatabaseMin: 1, ProtocolABI: version.ProtocolABI, APIVersion: version.APIVersion, UpstreamTag: "v1.14.1", UpstreamCommit: "1ac1a339cb1223e9c70eae14c44411c75033c02d", Files: map[string]File{}}
	names := []string{"splicore", "splicore.service", "splicore.yaml", "install.sh", "LICENSE", "NOTICE.md", "docs/INSTALLATION.md"}
	for _, name := range names {
		mode := os.FileMode(0644)
		if name == "splicore" || name == "install.sh" {
			mode = 0755
		}
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0700)
		b := []byte(name + "\n")
		if err := os.WriteFile(p, b, mode); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		m.Files[name] = File{hex.EncodeToString(sum[:]), int64(len(b)), uint32(mode)}
	}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0644)
	names = append(names, "manifest.json")
	sort.Strings(names)
	var checks strings.Builder
	for _, name := range names {
		h, err := HashFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&checks, "%s  %s\n", h, name)
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(checks.String()), 0644)
	return dir
}

func TestManifestInventoryRejectsTampering(t *testing.T) {
	for _, kind := range []string{"valid", "bytes", "extra", "checksums", "manifest", "missing"} {
		t.Run(kind, func(t *testing.T) {
			dir := fixture(t)
			switch kind {
			case "bytes":
				os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("changed"), 0644)
			case "extra":
				os.WriteFile(filepath.Join(dir, "unknown"), nil, 0644)
			case "checksums":
				os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("invalid"), 0644)
			case "manifest":
				os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0644)
			case "missing":
				os.Remove(filepath.Join(dir, "LICENSE"))
			}
			_, err := VerifyDirectory(dir, "linux/amd64")
			if (err == nil) != (kind == "valid") {
				t.Fatal(kind, err)
			}
		})
	}
}

func TestArchiveNamesRejectEscapes(t *testing.T) {
	for _, p := range []string{"../LICENSE", "/LICENSE", "docs/../LICENSE", "docs/../../evil.md", "licenses/a\\b", "licenses/x\nLICENSE", "."} {
		if AllowedMember(p) {
			t.Fatal("unsafe name", p)
		}
	}
}
