package xray

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
)

const ReferenceVersion = "26.3.27"
const ReferenceRelease = "https://github.com/XTLS/Xray-core/releases/tag/v26.3.27"

// Options is a bounded bootstrap surface, never Xray's public JSON schema.
type Options struct {
	BinaryPath       string
	RuntimeDirectory string
}

type Engine struct {
	options        Options
	mu             sync.Mutex
	status         ports.EngineStatus
	root           *os.Root
	lease          *os.File
	handles        map[*Handle]bool
	closed         bool
	inspect        func(context.Context, *ports.EngineStatus) string
	command        func(string, ...string) *exec.Cmd
	commandContext func(context.Context, string, ...string) *exec.Cmd
}

func New(options Options) *Engine {
	e := &Engine{options: options, status: ports.EngineStatus{Engine: "xray", ReferenceVersion: ReferenceVersion, Reason: "not_checked", RestartPolicy: "manual"}, handles: map[*Handle]bool{}, command: exec.Command, commandContext: exec.CommandContext}
	e.inspect = e.inspectBinary
	return e
}
func (*Engine) Metadata() ports.EngineMetadata {
	a := ports.Compiled
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		a = ports.UnsupportedPlatform
	}
	return ports.EngineMetadata{Roles: ports.Roles{Inbound: true, Outbound: true}, ID: "xray", Availability: a, RuntimeImplemented: a == ports.Compiled, ABI: 1, Protocols: []string{"vless"}}
}
func (*Engine) Capabilities() ports.Capabilities {
	return ports.Capabilities{
		EngineFeatures: v.TransportFeatures(binaryDigest() != ""),
		Transport:      ports.TransportCapabilities{Kinds: []string{"tcp"}, TCP: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true},
		Security:       ports.SecurityCapabilities{TLS: true, Reality: true, Flows: []string{"none"}},
		Identity:       ports.IdentityCapabilities{MultiUserNative: true, NativeStats: ports.Unsupported, AttributedPayload: ports.Unsupported},
		Policy:         ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported},
		Mutation:       ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable},
	}
}
func (e *Engine) Status() ports.EngineStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := e.status
	status.Features = featureAvailability(status.Available, status.Reason)
	return status
}
func featureAvailability(available bool, reason string) []ports.FeatureAvailability {
	return []ports.FeatureAvailability{{ID: "finalmask", Available: available, Reason: reason}, {ID: "sudoku", Available: available, Reason: reason}}
}
func (e *Engine) Version() string { return e.Status().InstalledVersion }
func (e *Engine) ValidateAvailability(ctx context.Context) error {
	status := ports.EngineStatus{Engine: "xray", ReferenceVersion: ReferenceVersion, RestartPolicy: "manual"}
	reason := e.inspect(ctx, &status)
	status.Reason = reason
	status.Available = reason == ""
	e.mu.Lock()
	e.status = status
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return unavailable("Xray engine closed")
	}
	if reason != "" {
		return unavailable("Xray artifact unavailable: " + reason)
	}
	return nil
}
func binaryDigest() string {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64":
		return "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed"
	case "windows/amd64":
		return "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1"
	default:
		return ""
	}
}
func (e *Engine) inspectBinary(ctx context.Context, status *ports.EngineStatus) string {
	if binaryDigest() == "" {
		return "unqualified_platform"
	}
	p := e.options.BinaryPath
	if p == "" {
		return "binary_missing"
	}
	if !safePath(p) {
		return "unsafe_binary_path"
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "binary_missing"
	}
	if resolved != filepath.Clean(p) {
		return "unsafe_binary_path"
	}
	f, err := os.Open(p)
	if err != nil {
		return "binary_missing"
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 || !executable(info) {
		return "bad_binary"
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, (256<<20)+1)); err != nil {
		return "bad_binary"
	}
	status.BinarySHA256 = hex.EncodeToString(h.Sum(nil))
	if status.BinarySHA256 != binaryDigest() {
		return "hash_mismatch"
	}
	versionCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(versionCtx, p, "version")
	cmd.Env = childEnvironment()
	var out boundedVersion
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if runOwned(cmd) != nil {
		return "version_failed"
	}
	version, ok := parseVersion(out.data)
	if !ok {
		return "version_mismatch"
	}
	status.InstalledVersion = version
	return ""
}
func parseVersion(data []byte) (string, bool) {
	fields := strings.Fields(string(data))
	if len(fields) < 2 || fields[0] != "Xray" || fields[1] != ReferenceVersion {
		return "", false
	}
	return fields[1], true
}
func runOwned(cmd *exec.Cmd) error {
	child, err := prepareProcess(cmd)
	if err != nil {
		return err
	}
	defer child.release()
	if err = cmd.Start(); err != nil {
		return err
	}
	if err = child.attach(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	return cmd.Wait()
}

type boundedVersion struct{ data []byte }

func (b *boundedVersion) Write(p []byte) (int, error) {
	b.data = append(b.data, p[:min(len(p), 4096-len(b.data))]...)
	return len(p), nil
}
func safePath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && identity.Label(p, 1024)
}
func unavailable(message string) error { return identity.Err(identity.Unavailable, message) }
func (e *Engine) Supports(in ports.RuntimeIntent) error {
	if in.Inbound.Protocol.Protocol != "vless" {
		return identity.Err(identity.UnsupportedEngineForProtocol, "UnsupportedEngineForProtocol")
	}
	_, err := validateIntent(in)
	return err
}
func (e *Engine) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := e.Supports(in); err != nil {
		return nil, err
	}
	factory, err := underlay.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	childLease, err := factory.AcquireChild(underlay.ScopeFrom(ctx, underlay.EngineChild))
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			childLease.Close()
		}
	}()
	if err := e.ValidateAvailability(ctx); err != nil {
		return nil, err
	}
	// Snapshot all mutable canonical state and TLS files into owned bytes. Handles
	// never retain caller slices or credential objects.
	b, err := render(in, access.Endpoint{Host: "127.0.0.1", Port: 1})
	if err != nil {
		return nil, err
	}
	h := newHandle(e, in.Inbound.Listeners[0].Endpoint, b)
	h.underlay = childLease
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		clear(b)
		return nil, unavailable("Xray engine closed")
	}
	e.handles[h] = true
	transferred = true
	return h, nil
}
func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	e.closed = true
	all := make([]*Handle, 0, len(e.handles))
	for h := range e.handles {
		all = append(all, h)
	}
	e.mu.Unlock()
	var result error
	for _, h := range all {
		if err := h.Close(ctx); err != nil {
			result = err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lease != nil {
		_ = e.lease.Close()
		e.lease = nil
	}
	if e.root != nil {
		_ = e.root.Close()
		e.root = nil
	}
	return result
}
