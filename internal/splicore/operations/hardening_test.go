package operations

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/clientruntime"
	"github.com/sagernet/sing-box/internal/splicore/config"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

type phase15DiagnosticSource struct {
	SupportSource
	status clientruntime.Status
}

func (s phase15DiagnosticSource) ClientStatus(context.Context) (clientruntime.Status, error) {
	return s.status, nil
}

func TestPhase15DiagnosticsReflectNativeProtocolsAndFailures(t *testing.T) {
	s := clientruntime.Status{Health: "degraded", State: client.Empty()}
	for _, protocol := range []string{"snell", "hysteria2", "tuic", "vless", "mieru", "SYNTHETIC_SECRET"} {
		s.State.Nodes = append(s.State.Nodes, client.RemoteNode{Protocol: access.ProtocolKey{Protocol: protocol}})
	}
	projection := clientProjection(context.Background(), phase15DiagnosticSource{status: s})
	for i, n := range projection.Nodes {
		if i < 5 && n.Protocol != s.State.Nodes[i].Protocol.Protocol {
			t.Fatal("supported protocol hidden", n.Protocol)
		}
	}
	b, err := json.Marshal(projection)
	if err != nil || strings.Contains(string(b), "SYNTHETIC_SECRET") {
		t.Fatal("untrusted diagnostic escaped projection", err)
	}
	for _, health := range []string{"degraded", "stopped", "SYNTHETIC_SECRET"} {
		s.Health = health
		checks := ClientDoctorChecks(&s)
		if checks[0].Status != "fail" {
			t.Fatal("enabled inconsistent runtime reported as informational", health)
		}
	}
}

func TestPhase15CanceledSupportLeavesNoArtifact(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	output := filepath.Join(dir, "support.tar.gz")
	c := config.Config{Schema: 1, StateDirectory: dir, API: config.API{UnixSocket: filepath.Join(dir, "control.sock")}}
	if err := SupportBundle(ctx, c, version.Current(), nil, output); !errors.Is(err, context.Canceled) {
		t.Error("canceled diagnostic did not report cancellation", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Error("canceled artifact remains", err)
	}
}
