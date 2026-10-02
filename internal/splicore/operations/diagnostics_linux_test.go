package operations

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/config"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/version"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type hostileSource struct{ secret string }

func (s hostileSource) System(context.Context) (application.System, error) {
	return application.System{NodeID: identity.ID(s.secret), Health: s.secret, Reasons: []string{s.secret}, Version: version.Info{Version: s.secret}, Engines: []ports.EngineStatus{{Engine: s.secret, Reason: s.secret, InstalledVersion: s.secret, BinarySHA256: s.secret}}}, nil
}
func (s hostileSource) Capabilities(context.Context, string, int) (application.CapabilityPage, error) {
	return application.CapabilityPage{Items: []application.Capability{{Protocol: s.secret, WireVersion: s.secret, FeatureProfile: s.secret}}}, nil
}
func (s hostileSource) Inbounds(context.Context) (application.InboundPage, error) {
	return application.InboundPage{Items: []application.InboundView{{Inbound: access.Inbound{Name: s.secret, Engine: s.secret, Protocol: access.ProtocolKey{Protocol: s.secret}, Tags: []string{s.secret}, Listeners: []access.Listener{{Transport: s.secret, Endpoint: access.Endpoint{Host: s.secret, Port: 443}}}}, Health: s.secret, Runtime: &ports.RuntimeStatus{ConfigArtifact: s.secret, Generation: s.secret, RuntimeDirectory: s.secret}}}}, nil
}

func TestSupportBundleBlockingSecretGate(t *testing.T) {
	secrets := []string{"snell-PSK-synthetic-DO-NOT-EXPORT", "hy2-password-synthetic-DO-NOT-EXPORT", "tuic-password-synthetic-DO-NOT-EXPORT", "123e4567-e89b-42d3-a456-426614174000", "reality-private-synthetic-DO-NOT-EXPORT", "mieru-password-synthetic-DO-NOT-EXPORT", "API-token-synthetic-DO-NOT-EXPORT"}
	joined := strings.Join(secrets, "-")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, secrets[0])
	if err := PrivateDirectory(state); err != nil {
		t.Fatal(err)
	}
	c := config.Config{Schema: 1, StateDirectory: state, KeyFile: filepath.Join(state, joined), API: config.API{UnixSocket: filepath.Join(state, joined+".sock")}, Xray: config.Xray{BinaryPath: filepath.Join(state, joined), RuntimeDirectory: state}}
	if err := PrivateDirectory(filepath.Join(state, "crashes")); err != nil {
		t.Fatal(err)
	}
	raw := ExitRecord{Version: joined, Commit: joined, Component: joined, Engine: joined, Protocol: joined, Classification: joined, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	b, _ := json.Marshal(raw)
	if err := os.WriteFile(filepath.Join(state, "crashes", "exit-synthetic.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "support.tar.gz")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := SupportBundle(ctx, c, version.Info{Version: joined, Commit: joined, SourceDigest: joined}, hostileSource{joined}, output); err != nil {
		t.Fatal(err)
	}
	i, err := os.Stat(output)
	if err != nil || i.Mode().Perm() != 0600 {
		t.Fatal("bundle not private", err)
	}
	f, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if strings.Contains(h.Name, secret) || strings.Contains(string(data), secret) {
				t.Fatalf("BLOCKING: secret in %s", h.Name)
			}
		}
		count++
	}
	if count != 7 {
		t.Fatalf("unexpected bundle inventory %d", count)
	}
	if err = SupportBundle(ctx, c, version.Current(), nil, output); err == nil {
		t.Fatal("overwrote existing support bundle")
	}
}

func TestInitializationNeverRekeysExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	c := config.Config{Schema: 1, StateDirectory: dir, KeyFile: filepath.Join(dir, "master.key"), API: config.API{UnixSocket: filepath.Join(dir, "api.sock")}}
	if err := Initialize(c); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(c.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = Initialize(c); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(c.KeyFile)
	if string(again) != string(key) {
		t.Fatal("key changed")
	}
	os.WriteFile(filepath.Join(dir, "state.db"), []byte("existing"), 0600)
	os.Remove(c.KeyFile)
	if err = Initialize(c); err == nil {
		t.Fatal("existing database silently rekeyed")
	}
	if _, err = os.Lstat(c.KeyFile); !os.IsNotExist(err) {
		t.Fatal("new key created")
	}
}

func TestConcurrentCrashRecordsBoundedAndSanitized(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	c := config.Config{Schema: 1, StateDirectory: dir, API: config.API{UnixSocket: filepath.Join(dir, "api.sock")}}
	var wg sync.WaitGroup
	errors := make(chan error, 32)
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); errors <- RecordExit(c, version.Current(), "secret-user-input") }()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "crashes"))
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "exit-") {
			count++
			b, _ := os.ReadFile(filepath.Join(dir, "crashes", e.Name()))
			if strings.Contains(string(b), "secret-user-input") {
				t.Fatal("raw error retained")
			}
		}
	}
	if count != 16 {
		t.Fatalf("retention=%d", count)
	}
}
