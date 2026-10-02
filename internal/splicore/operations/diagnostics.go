package operations

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/config"
	"github.com/sagernet/sing-box/internal/splicore/distribution"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

// SupportSource never offers exports or credential queries. All responses are
// projected onto fixed enums, booleans and counts before archive serialization.
type SupportSource interface {
	application.Queries
	Inbounds(context.Context) (application.InboundPage, error)
}

func enum(value string, allowed ...string) string {
	for _, s := range allowed {
		if value == s {
			return s
		}
	}
	return "unknown"
}

func PathChecks(c config.Config) []application.Check {
	checks := []application.Check{}
	for _, p := range []struct {
		name, path string
		max        os.FileMode
		kind       string
	}{
		{"state_permissions", c.StateDirectory, 0700, "directory"},
		{"database_permissions", filepath.Join(c.StateDirectory, "state.db"), 0600, "file"},
		{"master_key_permissions", c.KeyFile, 0600, "file"},
		{"runtime_permissions", filepath.Dir(c.API.UnixSocket), 0700, "directory"},
		{"socket_permissions", c.API.UnixSocket, 0660, "socket"},
		{"bootstrap_permissions", distribution.ConfigPath, 0640, "file"},
		{"unit", distribution.UnitPath, 0644, "file"},
	} {
		status, detail := "info", "absent or inaccessible"
		if p.path != "" {
			if i, err := os.Lstat(p.path); err == nil {
				resolved, e := filepath.EvalSymlinks(p.path)
				valid := e == nil && resolved == filepath.Clean(p.path) && i.Mode().Perm()&^p.max == 0 && validOwner(i)
				switch p.kind {
				case "directory":
					valid = valid && i.IsDir()
				case "file":
					valid = valid && i.Mode().IsRegular()
				case "socket":
					valid = valid && i.Mode()&os.ModeSocket != 0
				}
				if valid {
					status, detail = "pass", "type, owner and permissions checked"
				} else {
					status, detail = "fail", "unsafe type, owner, path or permissions"
				}
			}
		}
		checks = append(checks, application.Check{Name: p.name, Status: status, Detail: detail})
	}
	status := "info"
	if f, err := os.Open(distribution.ReceiptPath); err == nil {
		m, e := distribution.Decode(f)
		f.Close()
		exe, e2 := os.Executable()
		h, e3 := distribution.HashFile(exe)
		if e == nil && e2 == nil && e3 == nil && h == m.Files["splicore"].SHA256 {
			status = "pass"
		} else {
			status = "fail"
		}
	}
	checks = append(checks, application.Check{Name: "binary_identity", Status: status, Detail: "local receipt comparison"})
	checks = append(checks, systemdCheck())
	status = "info"
	if c.Xray.BinaryPath != "" {
		h, err := distribution.HashFile(c.Xray.BinaryPath)
		if err == nil && h == distribution.XrayHashes[runtime.GOOS+"/"+runtime.GOARCH] {
			status = "pass"
		} else {
			status = "fail"
		}
	}
	checks = append(checks, application.Check{Name: "xray_artifact", Status: status, Detail: "optional pinned 26.3.27 artifact"})
	return checks
}

type safeBuild struct {
	Product        string `json:"product"`
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	SourceDigest   string `json:"source_sha256"`
	Dirty          bool   `json:"dirty"`
	Platform       string `json:"platform"`
	ConfigSchema   int    `json:"config_schema"`
	DatabaseSchema int    `json:"db_schema"`
	ProtocolABI    int    `json:"protocol_abi"`
	API            string `json:"api_version"`
}

func buildSummary(v version.Info) safeBuild {
	s := safeBuild{Product: "Splicore", Version: "unknown", Commit: "unknown", SourceDigest: "unknown", Dirty: v.Dirty, Platform: runtime.GOOS + "/" + runtime.GOARCH, ConfigSchema: version.ConfigSchema, DatabaseSchema: version.DatabaseSchema, ProtocolABI: version.ProtocolABI, API: version.APIVersion}
	if regexp.MustCompile(`^0\.0\.0-dev(?:[.+-][0-9a-f]+)?$`).MatchString(v.Version) {
		s.Version = v.Version
	}
	if regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(v.Commit) {
		s.Commit = v.Commit
	}
	if regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(v.SourceDigest) {
		s.SourceDigest = v.SourceDigest
	}
	return s
}

type engineSummary struct {
	Engine    string `json:"engine"`
	Available bool   `json:"available"`
	Reference string `json:"reference"`
}
type systemSummary struct {
	Running             bool            `json:"running"`
	Health              string          `json:"health"`
	DBSchema            int             `json:"db_schema"`
	PendingMigrations   int             `json:"pending_migrations"`
	PendingTransactions int             `json:"pending_transactions"`
	Protocols           int             `json:"protocols"`
	Engines             []engineSummary `json:"engines"`
}
type listenerSummary struct {
	Protocol     string `json:"protocol"`
	Engine       string `json:"engine"`
	Health       string `json:"health"`
	Enabled      bool   `json:"enabled"`
	Transport    string `json:"transport"`
	AddressClass string `json:"address_class"`
	LowPort      bool   `json:"low_port"`
	Bindings     int    `json:"bindings"`
}

func addressClass(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return "hostname"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsUnspecified() {
		return "wildcard"
	}
	if ip.IsPrivate() {
		return "private"
	}
	return "other"
}

func recentCrashes(c config.Config) []ExitRecord {
	result := []ExitRecord{}
	dir := filepath.Join(c.StateDirectory, "crashes")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 64 {
		return result
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "exit-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		i, err := e.Info()
		if err != nil || !i.Mode().IsRegular() || i.Size() > 4096 || i.Mode().Perm()&0077 != 0 {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var raw ExitRecord
		err = json.NewDecoder(io.LimitReader(f, 4097)).Decode(&raw)
		f.Close()
		if err != nil {
			continue
		}
		v := buildSummary(version.Info{Version: raw.Version, Commit: raw.Commit})
		at, err := time.Parse(time.RFC3339Nano, raw.Timestamp)
		if err != nil {
			continue
		}
		result = append(result, ExitRecord{Schema: 1, Version: v.Version, Commit: v.Commit, Component: enum(raw.Component, "process", "engine", "protocol"), Engine: enum(raw.Engine, "native", "xray"), Protocol: enum(raw.Protocol, "none", "snell", "hysteria2", "tuic", "vless", "mieru"), Timestamp: at.UTC().Format(time.RFC3339Nano), Classification: ExitClass(raw.Classification)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Timestamp > result[j].Timestamp })
	if len(result) > 16 {
		result = result[:16]
	}
	return result
}

// SupportBundle creates a new private local archive. No raw input, database,
// configuration, panic stack, MESSAGE or export is copied into it.
func SupportBundle(ctx context.Context, c config.Config, v version.Info, q SupportSource, output string) error {
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return fmt.Errorf("bundle requires a clean absolute output path")
	}
	if err := PrivateDirectory(filepath.Dir(output)); err != nil {
		return err
	}
	system := systemSummary{Health: "unavailable", Engines: []engineSummary{}}
	listeners := []listenerSummary{}
	checks := PathChecks(c)
	if q != nil {
		if s, err := q.System(ctx); err == nil {
			system.Running = true
			system.Health = enum(s.Health, "healthy", "degraded", "recovery_required")
			system.DBSchema = s.DBSchema
			system.PendingMigrations = s.Foundation.PendingMigrations
			system.PendingTransactions = s.Foundation.PendingTransactions
			system.Protocols = s.Foundation.Protocols
			for _, e := range s.Engines {
				ref := "embedded"
				if e.Engine == "xray" {
					ref = "26.3.27"
				}
				system.Engines = append(system.Engines, engineSummary{enum(e.Engine, "native", "xray"), e.Available, ref})
			}
		}
		if page, err := q.Inbounds(ctx); err == nil {
			for _, i := range page.Items {
				for _, l := range i.Inbound.Listeners {
					listeners = append(listeners, listenerSummary{Protocol: enum(i.Inbound.Protocol.Protocol, "snell", "hysteria2", "tuic", "vless", "mieru"), Engine: enum(i.Inbound.Engine, "native", "xray"), Health: enum(i.Health, "healthy", "failed", "stopped", "prepared", "starting"), Enabled: i.Inbound.Enabled, Transport: enum(l.Transport, "tcp", "udp"), AddressClass: addressClass(l.Endpoint.Host), LowPort: l.Endpoint.Port > 0 && l.Endpoint.Port < 1024, Bindings: len(i.Bindings)})
				}
			}
		}
		if page, err := q.Capabilities(ctx, "", 200); err == nil {
			checks = append(checks, application.Check{Name: "protocol_registry", Status: "pass", Detail: fmt.Sprintf("%d entries", len(page.Items))})
		}
	}
	files := map[string]any{
		"client.redacted.json": clientProjection(ctx, q),
		"version.json":         buildSummary(v), "system.json": system, "doctor.json": checks,
		"config.redacted.json": struct {
			Schema           int  `json:"schema"`
			StateCanonical   bool `json:"state_canonical"`
			RuntimeCanonical bool `json:"runtime_canonical"`
			KeyConfigured    bool `json:"key_configured"`
			XrayConfigured   bool `json:"xray_configured"`
		}{c.Schema, c.StateDirectory == distribution.StatePath, filepath.Dir(c.API.UnixSocket) == distribution.RuntimePath, c.KeyFile != "", c.Xray.BinaryPath != ""},
		"listeners.json": listeners, "crashes.json": recentCrashes(c), "journal.summary.json": journalSummary(ctx),
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("bundle output must be new")
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(output)
		}
	}()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b, e := json.MarshalIndent(files[name], "", "  ")
		if e != nil {
			return e
		}
		b = append(b, '\n')
		if len(b) > 1<<20 {
			return fmt.Errorf("support projection exceeds limit")
		}
		if err = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err = tw.Write(b); err != nil {
			return err
		}
	}
	if err = tw.Close(); err == nil {
		err = gz.Close()
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Close()
	}
	if err != nil {
		return err
	}
	ok = true
	return nil
}
