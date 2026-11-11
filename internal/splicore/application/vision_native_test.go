package application_test

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	mc "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	sc "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	v "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/registry/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"path/filepath"
	"strings"
	"testing"
)

func TestVisionNativeCreationProjectionAndSecretBoundary(t *testing.T) {
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, testfixture.Phase5)
	defer stop(t, s, store)
	ctx := context.Background()
	for _, security := range []v.Security{v.TLS, v.Reality} {
		if security == v.Reality && !v.RealityCompiled {
			continue
		}
		settings := v.Settings{Security: security, Flow: v.Vision, Transport: "tcp", PacketEncoding: "xudp"}
		key := ""
		if security == v.TLS {
			material := testkit.TLSForName(t, "vision.synthetic.test")
			settings.TLS = &material
		} else {
			private, _, e := v.GenerateServerKey()
			if e != nil {
				t.Fatal(e)
			}
			key = private.Material.Reveal()
			settings.Reality = &v.RealitySettings{ServerName: "vision.synthetic.test", Target: target(t), ShortIDs: []v.ShortID{"abcd"}}
		}
		a := applyVLESS(t, s, vlessDoc(t, freePort(t), settings, key))
		view, e := s.Inbound(ctx, a.InboundID)
		if e != nil || view.Health != "healthy" {
			t.Fatal(e)
		}
		diagnostics, e := s.Doctor(ctx, "test")
		if e != nil {
			t.Fatal(e)
		}
		b, _ := json.Marshal([]any{view, diagnostics})
		if key != "" && strings.Contains(string(b), key) {
			t.Fatal("private key leaked")
		}
		if security == v.Reality {
			out, e := s.ExportClient(ctx, a.InboundID, application.ExportRequest{Format: ports.URI, BindingID: a.Bindings[0].BindingID})
			if e != nil {
				t.Fatal(e)
			}
			b, _ := json.Marshal(out)
			if !strings.Contains(string(b), "flow=xtls-rprx-vision") {
				t.Fatal("flow lost")
			}
		}
		// Unrepresentable mask exports must fail, preserving the protocol boundary.
		settings.Stream = &sc.Config{Kind: "tcp", FinalMask: &mc.Config{TCP: []mc.Mask{{Type: "sudoku", Settings: json.RawMessage(`{"password":"synthetic-mask-secret"}`)}}}}
		a = applyVLESS(t, s, vlessDoc(t, freePort(t), settings, key))
		if _, e = s.ExportClient(ctx, a.InboundID, application.ExportRequest{Format: ports.URI, BindingID: a.Bindings[0].BindingID}); e == nil {
			t.Fatal("mask silently dropped")
		}
		view, _ = s.Inbound(ctx, a.InboundID)
		b, _ = json.Marshal(view)
		if strings.Contains(string(b), "synthetic-mask-secret") {
			t.Fatal("mask secret leaked")
		}
	}
}
