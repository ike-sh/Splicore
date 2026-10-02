package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/transportmask"
	"os"
	"path/filepath"
	"testing"
)

func maskedFixture(t *testing.T) ports.RuntimeIntent {
	in := fixture(t)
	s, _ := v.Decode(in.Inbound.Settings.Data)
	s.EngineOptions = &transportmask.Options{FinalMask: &transportmask.FinalMask{TCP: []transportmask.TCPMask{{Type: "sudoku", Settings: &transportmask.Sudoku{ASCII: "prefer_ascii", PaddingMax: 3}}}}}
	in.Inbound.Settings.Data, _ = json.Marshal(s)
	id, _ := identity.NewID()
	password, err := transportmask.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	in.ServerCredentials = []access.Credential{{ID: id, OwnerInboundID: &in.Inbound.ID, Kind: access.Password, Schema: 1, State: "active", Payload: access.PasswordPayload{Password: password}, Stamp: in.Inbound.Stamp}}
	return in
}

func TestSudokuRendererSnapshotAndOwnership(t *testing.T) {
	in := maskedFixture(t)
	password := in.ServerCredentials[0].Payload.(access.PasswordPayload).Password
	b, err := render(in, access.Endpoint{Host: "127.0.0.1", Port: 23456})
	if err != nil {
		t.Fatal(err)
	}
	var config configuration
	if json.Unmarshal(b, &config) != nil {
		t.Fatal("render JSON")
	}
	mask := config.Inbounds[0].Stream.FinalMask
	if mask == nil || len(mask.TCP) != 1 || mask.TCP[0].Type != "sudoku" || mask.TCP[0].Settings.Password != password.Reveal() || mask.TCP[0].Settings.ASCII != "prefer_ascii" || mask.TCP[0].Settings.PaddingMin != 0 || mask.TCP[0].Settings.PaddingMax != 3 {
		t.Fatal("pinned mask mapping")
	}
	e := helperEngine(t, "echo")
	prepared, err := e.Compile(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(*Handle)
	before := append([]byte(nil), h.config...)
	clear(in.Inbound.Settings.Data)
	in.ServerCredentials[0].Payload = access.PasswordPayload{}
	if !bytes.Equal(before, h.config) || !bytes.Contains(h.config, []byte(password.Reveal())) {
		t.Fatal("Compile retained mutable caller state")
	}
	_ = h.Close(context.Background())
	in = maskedFixture(t)
	in.ServerCredentials[0].OwnerInboundID = &in.Credentials[0].ID
	if _, err := render(in, access.Endpoint{Host: "127.0.0.1", Port: 23456}); err == nil {
		t.Fatal("wrong secret owner accepted")
	}
	in = maskedFixture(t)
	in.ServerCredentials = nil
	if _, err := render(in, access.Endpoint{Host: "127.0.0.1", Port: 23456}); err == nil {
		t.Fatal("missing feature secret accepted")
	}
}

func TestFeatureArtifactAvailabilityFailClosedAndSnapshot(t *testing.T) {
	for _, path := range []string{"", filepath.Join(t.TempDir(), "wrong-xray")} {
		if path != "" {
			if os.WriteFile(path, []byte("synthetic non-artifact"), 0700) != nil {
				t.Fatal("fixture")
			}
		}
		e := New(Options{BinaryPath: path, RuntimeDirectory: filepath.Join(t.TempDir(), "runtime")})
		if e.ValidateAvailability(context.Background()) == nil {
			t.Fatal("unqualified feature artifact accepted")
		}
		status := e.Status()
		if len(status.Features) != 2 || status.Features[0].Available || status.Features[1].Available {
			t.Fatal("missing/wrong artifact advertises feature")
		}
		status.Features[0].Available = true
		status.Features[0].Reason = "changed"
		if e.Status().Features[0].Available || e.Status().Features[0].Reason == "changed" {
			t.Fatal("status snapshot aliases state")
		}
		_ = e.Close(context.Background())
	}
}

func FuzzSudokuRendererBoundary(f *testing.F) {
	f.Add([]byte(`{"security":"none","flow":"none","transport":"tcp","packet_encoding":"xudp","engine_options":{"finalmask":{"tcp":[{"type":"sudoku","settings":{"ascii":"prefer_ascii","padding_min":0,"padding_max":3}}]}}}`), "0123456789ABCDEF0123456789ABCDEF")
	f.Add([]byte(`{"security":"none","flow":"none","engine_options":null}`), "invalid")
	f.Fuzz(func(t *testing.T, data []byte, password string) {
		in := maskedFixture(t)
		in.Inbound.Settings.Data = append([]byte(nil), data...)
		in.ServerCredentials[0].Payload = access.PasswordPayload{Password: secret.New(password)}
		b, err := render(in, access.Endpoint{Host: "127.0.0.1", Port: 12345})
		if err != nil {
			return
		}
		var config configuration
		if json.Unmarshal(b, &config) != nil || len(config.Inbounds) != 1 {
			t.Fatal("invalid accepted mask configuration")
		}
		mask := config.Inbounds[0].Stream.FinalMask
		if mask == nil || len(mask.TCP) != 1 || mask.TCP[0].Type != "sudoku" || mask.TCP[0].Settings.Password != password || mask.TCP[0].Settings.ASCII != "prefer_ascii" || mask.TCP[0].Settings.PaddingMin != 0 || mask.TCP[0].Settings.PaddingMax != 3 {
			t.Fatal("renderer expanded bounded mask contract")
		}
	})
}
