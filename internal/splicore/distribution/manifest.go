// Package distribution owns the local artifact and installation contract.
package distribution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/version"
)

const BinaryPath = "/usr/local/bin/splicore"
const ConfigPath = "/etc/splicore/splicore.yaml"
const StatePath = "/var/lib/splicore"
const RuntimePath = "/run/splicore"
const UnitPath = "/etc/systemd/system/splicore.service"
const ReceiptPath = "/etc/splicore/install.json"
const UpgradePath = "/var/lib/splicore-upgrades"
const Ownership = "Splicore layout 1\n"

type File struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Mode   uint32 `json:"mode"`
}
type Manifest struct {
	Schema         int             `json:"schema"`
	Product        string          `json:"product"`
	Version        string          `json:"version"`
	Channel        string          `json:"channel"`
	Qualification  string          `json:"qualification"`
	GitCommit      string          `json:"git_commit"`
	SourceDirty    bool            `json:"source_dirty"`
	SourceSHA256   string          `json:"source_sha256"`
	BuildTime      string          `json:"build_time"`
	GoVersion      string          `json:"go_version"`
	GOOS           string          `json:"goos"`
	GOARCH         string          `json:"goarch"`
	BuildTags      string          `json:"build_tags"`
	ConfigSchema   int             `json:"config_schema"`
	DatabaseSchema int             `json:"db_schema"`
	DatabaseMin    int             `json:"db_schema_min"`
	ProtocolABI    int             `json:"protocol_abi"`
	APIVersion     string          `json:"api_version"`
	UpstreamTag    string          `json:"upstream_tag"`
	UpstreamCommit string          `json:"upstream_commit"`
	Files          map[string]File `json:"files"`
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var versionPattern = regexp.MustCompile(`^(?:0\.0\.0-dev(?:[.+-][A-Za-z0-9.-]+)?|0\.1\.0)$`)

func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Decode(r io.Reader) (Manifest, error) {
	var m Manifest
	b, err := io.ReadAll(io.LimitReader(r, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return m, fmt.Errorf("manifest exceeds size limit")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return m, fmt.Errorf("invalid distribution manifest")
	}
	if m.Schema != 1 || m.Product != "Splicore" || !versionPattern.MatchString(m.Version) || m.Channel != "development" || m.Qualification != "experimental" || !commitPattern.MatchString(m.GitCommit) || !digestPattern.MatchString(m.SourceSHA256) || m.GOOS != "linux" || m.GOARCH != "amd64" && m.GOARCH != "arm64" || m.ConfigSchema != version.ConfigSchema || m.DatabaseSchema < 1 || m.DatabaseSchema > version.DatabaseSchema || m.DatabaseMin < 1 || m.DatabaseMin > m.DatabaseSchema || m.ProtocolABI != version.ProtocolABI || m.APIVersion != version.APIVersion || m.UpstreamTag != "v1.14.1" || m.UpstreamCommit != "1ac1a339cb1223e9c70eae14c44411c75033c02d" {
		return m, fmt.Errorf("incompatible distribution identity")
	}
	if _, err = time.Parse(time.RFC3339, m.BuildTime); err != nil || !strings.HasPrefix(m.GoVersion, "go1.") || m.BuildTags != "with_quic,with_utls" && m.BuildTags != "with_quic,with_utls,with_gvisor" {
		return m, fmt.Errorf("invalid build provenance")
	}
	if len(m.Files) < 7 || len(m.Files) > 256 {
		return m, fmt.Errorf("invalid distribution file count")
	}
	for p, f := range m.Files {
		if !AllowedMember(p) || !digestPattern.MatchString(f.SHA256) || f.Bytes < 0 || f.Bytes > 128<<20 || f.Mode != 0644 && f.Mode != 0755 {
			return m, fmt.Errorf("unsafe distribution member")
		}
	}
	for _, p := range []string{"splicore", "splicore.service", "splicore.yaml", "install.sh", "LICENSE", "NOTICE.md", "docs/INSTALLATION.md"} {
		if _, ok := m.Files[p]; !ok {
			return m, fmt.Errorf("required distribution member absent")
		}
	}
	return m, nil
}
func AllowedMember(p string) bool {
	if p == "" || strings.ContainsAny(p, "\\\x00\r\n") || strings.HasPrefix(p, "/") || filepath.ToSlash(filepath.Clean(p)) != p || p == "." || strings.HasPrefix(p, "../") {
		return false
	}
	switch p {
	case "splicore", "splicore.service", "splicore-tun.conf", "splicore.yaml", "install.sh", "LICENSE", "NOTICE.md":
		return true
	}
	return strings.HasPrefix(p, "docs/") && strings.HasSuffix(p, ".md") || strings.HasPrefix(p, "licenses/") && regexp.MustCompile(`^[A-Za-z0-9._/-]+$`).MatchString(p)
}
func VerifyDirectory(path, platform string) (Manifest, error) {
	var m Manifest
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return m, fmt.Errorf("package directory must be clean absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return m, fmt.Errorf("package directory must not use symlinks")
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return m, err
	}
	defer r.Close()
	info, err := r.Lstat("manifest.json")
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return m, fmt.Errorf("unsafe manifest file")
	}
	f, err := r.Open("manifest.json")
	if err != nil {
		return m, err
	}
	defer f.Close()
	m, err = Decode(f)
	if err != nil {
		return m, err
	}
	if m.DatabaseSchema != version.DatabaseSchema {
		return m, fmt.Errorf("package database schema differs from verifier")
	}
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}
	if m.GOOS+"/"+m.GOARCH != platform {
		return m, fmt.Errorf("package platform mismatch")
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == path {
			return nil
		}
		name, _ := filepath.Rel(path, p)
		name = filepath.ToSlash(name)
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("package symlink prohibited")
		}
		if d.IsDir() {
			if name != "docs" && name != "licenses" && !strings.HasPrefix(name, "licenses/") {
				return fmt.Errorf("unknown package directory")
			}
			return nil
		}
		if name == "manifest.json" || name == "SHA256SUMS" {
			i, e := d.Info()
			if e != nil || !i.Mode().IsRegular() {
				return fmt.Errorf("unsafe manifest/checksum file")
			}
			return nil
		}
		expected, ok := m.Files[name]
		if !ok {
			return fmt.Errorf("unexpected package member")
		}
		i, e := d.Info()
		if e != nil || !i.Mode().IsRegular() || i.Size() != expected.Bytes || runtime.GOOS != "windows" && uint32(i.Mode().Perm()) != expected.Mode {
			return fmt.Errorf("package member type/size/mode mismatch")
		}
		got, e := HashFile(p)
		if e != nil || got != expected.SHA256 {
			return fmt.Errorf("package member checksum mismatch")
		}
		seen[name] = true
		return nil
	})
	if err != nil {
		return m, err
	}
	if len(seen) != len(m.Files) {
		return m, fmt.Errorf("incomplete package")
	}
	info, err = r.Lstat("SHA256SUMS")
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return m, fmt.Errorf("unsafe checksum file")
	}
	checks, err := r.ReadFile("SHA256SUMS")
	if err != nil || len(checks) > 64<<10 {
		return m, fmt.Errorf("missing or oversized checksums")
	}
	names := []string{"manifest.json"}
	for p := range m.Files {
		names = append(names, p)
	}
	sort.Strings(names)
	var expected strings.Builder
	for _, p := range names {
		h := m.Files[p].SHA256
		if p == "manifest.json" {
			h, err = HashFile(filepath.Join(path, p))
			if err != nil {
				return m, err
			}
		}
		fmt.Fprintf(&expected, "%s  %s\n", h, p)
	}
	if string(checks) != expected.String() {
		return m, fmt.Errorf("checksum inventory mismatch")
	}
	return m, nil
}
