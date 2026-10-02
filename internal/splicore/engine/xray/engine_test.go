package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
)

func fixture(t testing.TB) ports.RuntimeIntent {
	t.Helper()
	id := func() identity.ID {
		value, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	stamp := identity.NewStamp(time.Now())
	i := access.Inbound{ID: id(), NodeID: id(), Name: "synthetic", Protocol: v.Key(v.Plain), Engine: "xray", Enabled: true, Listeners: []access.Listener{{ID: id(), Transport: "tcp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 12345}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: id(), Endpoint: access.Endpoint{Host: "edge.synthetic.test", Port: 443}}}, Tags: []string{}, Stamp: stamp}
	i.Settings = access.Settings{Schema: 1, Data: json.RawMessage(`{"security":"none","flow":"none","transport":"tcp","packet_encoding":"xudp"}`)}
	a, cid, bid := id(), id(), id()
	b := access.Binding{ID: bid, AccountID: a, CredentialID: cid, InboundID: i.ID, Enabled: true, Stamp: stamp}
	c := access.Credential{ID: cid, OwnerAccountID: &a, Kind: access.UUID, Schema: 1, State: "active", Payload: access.UUIDPayload{UUID: secret.New(string(id()))}, Stamp: stamp}
	return ports.RuntimeIntent{Inbound: i, Bindings: []access.Binding{b}, Credentials: []access.Credential{c}}
}
func helperEngine(t *testing.T, mode string) *Engine {
	t.Helper()
	e := New(Options{BinaryPath: os.Args[0], RuntimeDirectory: filepath.Join(t.TempDir(), "runtime")})
	e.inspect = func(context.Context, *ports.EngineStatus) string { return "" }
	e.command = func(_ string, args ...string) *exec.Cmd {
		return exec.Command(os.Args[0], "-test.run=^TestChildHelper$", "--", mode, args[len(args)-1])
	}
	e.commandContext = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestChildHelper$", "--", "check", args[len(args)-1])
	}
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	return e
}

// Separate fixtures exercise OS process handles and sockets. Production
// constructors always use the pinned artifact validator and direct execution.
func TestChildHelper(t *testing.T) {
	sep := -1
	for n, arg := range os.Args {
		if arg == "--" {
			sep = n
			break
		}
	}
	if sep < 0 {
		return
	}
	mode, path := os.Args[sep+1], os.Args[sep+2]
	if mode == "check" {
		os.Exit(0)
	}
	if mode == "exit" {
		os.Exit(23)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		os.Exit(24)
	}
	var c configuration
	if json.Unmarshal(b, &c) != nil {
		os.Exit(25)
	}
	if mode == "no-listener" {
		unexpected, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			os.Exit(27)
		}
		_, _ = unexpected.Accept()
		os.Exit(0)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(c.Inbounds[0].Listen, strconv.Itoa(int(c.Inbounds[0].Port))))
	if err != nil {
		os.Exit(26)
	}
	_, _ = os.Stderr.Write([]byte(strings.Repeat("synthetic-private-log\n", 10000)))
	for {
		conn, err := listener.Accept()
		if err != nil {
			os.Exit(0)
		}
		go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
	}
}
func prepareHelper(t *testing.T, e *Engine) *Handle {
	t.Helper()
	in := fixture(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	in.Inbound.Listeners[0].Endpoint.Port = uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	prepared, err := e.Compile(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return prepared.(*Handle)
}
func address(h *Handle) string {
	return net.JoinHostPort(h.endpoint.Host, strconv.Itoa(int(h.endpoint.Port)))
}
func roundTrip(t *testing.T, h *Handle) {
	t.Helper()
	c, err := net.DialTimeout("tcp", address(h), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 9)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "synthetic" {
		t.Fatal("relay", err)
	}
}
func TestSupervisorAdmissionOwnershipCrashCleanup(t *testing.T) {
	e := helperEngine(t, "echo")
	h := prepareHelper(t, e)
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !listenerOwned(h.RuntimeStatus().PID, h.privatePort) || listenerOwned(os.Getpid(), h.privatePort) {
		t.Fatal("listener ownership")
	}
	if err := h.Start(context.Background()); err == nil {
		t.Fatal("double start")
	}
	c, err := net.DialTimeout("tcp", address(h), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte("precommit"))
	b := make([]byte, 1)
	if _, err = c.Read(b); err == nil {
		t.Fatal("admitted before commit")
	}
	_ = c.Close()
	h.Activate()
	roundTrip(t, h)
	status := h.RuntimeStatus()
	file, err := os.Stat(status.ConfigArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" && file.Mode().Perm() != 0600 {
		t.Fatal("artifact permissions")
	}
	unrelated := prepareHelper(t, e)
	if unrelated.Start(context.Background()) != nil {
		t.Fatal("second process")
	}
	unrelated.Activate()
	h.child.terminate(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = h.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	status = h.RuntimeStatus()
	if status.Health != "failed" || status.ExitCode == nil || h.Health(ctx) == nil {
		t.Fatal("crash status")
	}
	if _, err = os.Stat(status.ConfigArtifact); !os.IsNotExist(err) {
		t.Fatal("crash artifact retained")
	}
	if h.Close(ctx) != nil || h.Close(ctx) != nil {
		t.Fatal("stop")
	}
	roundTrip(t, unrelated)
}
func TestSupervisorConcurrentCloseAndTraffic(t *testing.T) {
	e := helperEngine(t, "echo")
	h := prepareHelper(t, e)
	if h.Start(context.Background()) != nil {
		t.Fatal("start")
	}
	h.Activate()
	var workers sync.WaitGroup
	for n := 0; n < 16; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			c, err := net.DialTimeout("tcp", address(h), time.Second)
			if err == nil {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				_, _ = c.Write([]byte("data"))
				_, _ = io.Copy(io.Discard, c)
			}
			_ = h.RuntimeStatus()
			_ = h.Health(context.Background())
		}()
	}
	for n := 0; n < 4; n++ {
		workers.Add(1)
		go func() { defer workers.Done(); _ = h.Close(context.Background()) }()
	}
	workers.Wait()
	l, err := net.Listen("tcp", address(h))
	if err != nil {
		t.Fatal("listener leak")
	}
	_ = l.Close()
}
func TestSupervisorStartFailuresAndStaleCleanup(t *testing.T) {
	for _, mode := range []string{"exit", "no-listener"} {
		t.Run(mode, func(t *testing.T) {
			e := helperEngine(t, mode)
			h := prepareHelper(t, e)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if h.Start(ctx) == nil {
				t.Fatal("unexpected health")
			}
			if h.RuntimeStatus().Health != "failed" {
				t.Fatal("failure status")
			}
			if h.Wait(context.Background()) != nil {
				t.Fatal("not joined")
			}
			if _, err := os.Stat(h.RuntimeStatus().ConfigArtifact); !os.IsNotExist(err) {
				t.Fatal("failure artifact leak")
			}
		})
	}
	e := helperEngine(t, "echo")
	h := prepareHelper(t, e)
	conflict, err := net.Listen("tcp", address(h))
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	if err = h.Start(context.Background()); err == nil {
		t.Fatal("port conflict")
	}
	id, _ := identity.NewID()
	stale := filepath.Join(e.options.RuntimeDirectory, "generation-"+string(id))
	if err = os.MkdirAll(stale, 0700); err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(filepath.Join(stale, "config.json"), []byte("synthetic-stale-secret"), 0600) != nil {
		t.Fatal("stale fixture")
	}
	other := filepath.Join(e.options.RuntimeDirectory, "operator-note")
	_ = os.WriteFile(other, []byte("retain"), 0600)
	_, _, err = e.generation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale cleanup")
	}
	if _, err = os.Stat(other); err != nil {
		t.Fatal("unowned file removed")
	}
	second := New(e.options)
	defer second.Close(context.Background())
	if _, _, err = second.generation(); err == nil {
		t.Fatal("root lease not exclusive")
	}
}
func TestSupervisorInvalidArtifactAndOwnedSnapshot(t *testing.T) {
	for _, stage := range []string{"validation", "snapshot", "path"} {
		t.Run(stage, func(t *testing.T) {
			e := helperEngine(t, "echo")
			h := prepareHelper(t, e)
			switch stage {
			case "validation":
				e.commandContext = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
					return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestChildHelper$", "--", "exit", args[len(args)-1])
				}
			case "snapshot":
				h.config = []byte("invalid owned snapshot")
			case "path":
				e.options.RuntimeDirectory = "../escape"
			}
			if h.Start(context.Background()) == nil {
				t.Fatal("invalid generation admitted")
			}
			if h.Wait(context.Background()) != nil {
				t.Fatal("cleanup not joined")
			}
			status := h.RuntimeStatus()
			if status.ConfigArtifact != "" {
				if _, err := os.Stat(status.ConfigArtifact); !os.IsNotExist(err) {
					t.Fatal("artifact retained")
				}
			}
		})
	}
	e := helperEngine(t, "echo")
	in := fixture(t)
	original := in.Credentials[0].Payload.(access.UUIDPayload).UUID.Reveal()
	prepared, err := e.Compile(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(*Handle)
	in.Inbound.Settings.Data[0] = 'x'
	in.Bindings[0].Enabled = false
	in.Credentials[0].Payload = access.UUIDPayload{UUID: secret.New("changed-caller")}
	if !strings.Contains(string(h.config), original) || strings.Contains(string(h.config), "changed-caller") {
		t.Fatal("prepared state aliases caller")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", h, h), original) {
		t.Fatal("handle diagnostic leak")
	}
}
func TestAvailabilityAndRendererBoundaries(t *testing.T) {
	ctx := context.Background()
	for _, s := range []string{"", "Xray 99.0.0", "Xray 26.3.27-extra", "not-Xray 26.3.27"} {
		if _, ok := parseVersion([]byte(s)); ok {
			t.Fatal("wrong version accepted")
		}
	}
	if version, ok := parseVersion([]byte("Xray 26.3.27 (Xray, Penetrates Everything.)")); !ok || version != ReferenceVersion {
		t.Fatal("version detection")
	}
	for _, p := range []string{"", "relative", "/missing/xray"} {
		e := New(Options{BinaryPath: p})
		if e.ValidateAvailability(ctx) == nil || e.Status().Available {
			t.Fatal("invalid binary available")
		}
	}
	p := filepath.Join(t.TempDir(), "bad-xray")
	_ = os.WriteFile(p, []byte("bad executable"), 0700)
	e := New(Options{BinaryPath: p})
	if e.ValidateAvailability(ctx) == nil {
		t.Fatal("bad executable")
	}
	if safePath(t.TempDir()+string(os.PathSeparator)+".."+string(os.PathSeparator)+"escape") || safePath("../escape") {
		t.Fatal("path traversal")
	}
	in := fixture(t)
	b, err := render(in, access.Endpoint{Host: "127.0.0.1", Port: 43210})
	if err != nil {
		t.Fatal(err)
	}
	var config configuration
	_ = json.Unmarshal(b, &config)
	if config.Inbounds[0].Settings.Clients[0].ID != in.Credentials[0].Payload.(access.UUIDPayload).UUID.Reveal() || config.Inbounds[0].Stream.Network != "raw" {
		t.Fatal("canonical render")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", config, config), config.Inbounds[0].Settings.Clients[0].ID) {
		t.Fatal("config formatting leak")
	}
	in.Inbound.Settings.Data = json.RawMessage(`{"security":"none","flow":"xtls-rprx-vision","transport":"tcp","packet_encoding":"xudp"}`)
	if _, err = e.Compile(ctx, in); err == nil || !strings.Contains(err.Error(), "not_implemented") {
		t.Fatal("Vision must reject before artifact access")
	}
	var out boundedVersion
	for n := 0; n < 10; n++ {
		_, _ = out.Write(make([]byte, 4096))
	}
	if len(out.data) != 4096 {
		t.Fatal("unbounded version output")
	}
	var logs discardLog
	for n := 0; n < 10; n++ {
		_, _ = logs.Write(make([]byte, 1<<20))
	}
	if logs.bytes.Load() != 1<<20 {
		t.Fatal("unbounded log accounting")
	}
}
func FuzzRuntimePath(f *testing.F) {
	for _, s := range []string{"../escape", "/tmp/../escape", "/tmp/splicore", "", "C:\\runtime"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if safePath(p) && (!filepath.IsAbs(p) || filepath.Clean(p) != p) {
			t.Fatal("unsafe path")
		}
	})
}
func FuzzRendererBoundary(f *testing.F) {
	f.Add([]byte(`{"security":"none","flow":"none","transport":"tcp","packet_encoding":"xudp"}`))
	f.Add([]byte(`{"flow":"xtls-rprx-vision"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		in := fixture(t)
		in.Inbound.Settings.Data = append([]byte(nil), data...)
		b, err := render(in, access.Endpoint{Host: "127.0.0.1", Port: 12345})
		if err == nil {
			var c configuration
			if json.Unmarshal(b, &c) != nil || len(c.Inbounds) != 1 || strings.Contains(string(b), "xtls-rprx-vision") {
				t.Fatal("invalid rendered configuration")
			}
		}
	})
}
