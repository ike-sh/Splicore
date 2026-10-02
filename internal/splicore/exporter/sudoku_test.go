package exporter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/exporter"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/transportmask"
	"strings"
	"testing"
)

func TestSudokuClientRequirementsAndUnsupportedFormats(t *testing.T) {
	p, privateKey := vlessProfile(t, "edge.test")
	p.Protocol = v.Key(v.Plain)
	p.TLS = clientprofile.TLS{}
	p.UDPPayload = false
	p.Options.Data, _ = json.Marshal(v.ClientOptions{Security: v.Plain, Flow: v.NoFlow, PacketEncoding: "xudp"})
	password, err := transportmask.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	p.TransportRequirements = &transportmask.ClientRequirements{Password: password, Options: transportmask.Options{FinalMask: &transportmask.FinalMask{TCP: []transportmask.TCPMask{{Type: "sudoku", Settings: &transportmask.Sudoku{ASCII: "prefer_ascii", PaddingMax: 3}}}}}}
	for _, target := range []ports.ExportTarget{{Format: ports.Mihomo, ClientVersion: "1.19.30"}, {Format: ports.SingBox, ClientVersion: "1.14.1"}, {Format: ports.Surge, ClientVersion: "6.7.0"}, {Format: ports.URI}, {Format: ports.Xray, ClientVersion: "unknown"}} {
		if data, err := (exporter.VLESS{Target: target.Format}).Export(context.Background(), p, target); err == nil || len(data) != 0 {
			t.Fatal("unqualified client silently loses mask")
		}
	}
	data, err := (exporter.VLESS{Target: ports.Xray}).Export(context.Background(), p, ports.ExportTarget{Format: ports.Xray, ClientVersion: "26.3.27"})
	if err != nil || !strings.Contains(string(data), password.Reveal()) || strings.Contains(string(data), privateKey) || strings.Contains(string(data), "engine") {
		t.Fatal("explicit wire requirements export")
	}
	ordinary, _ := json.Marshal(p)
	if strings.Contains(string(ordinary), password.Reveal()) || strings.Contains(fmt.Sprintf("%+v %#v", p, p), password.Reveal()) {
		t.Fatal("implicit shared secret leak")
	}
	p.TransportRequirements.Options.FinalMask.TCP[0].Settings.ASCII = "custom"
	if data, err := (exporter.VLESS{Target: ports.Xray}).Export(context.Background(), p, ports.ExportTarget{Format: ports.Xray, ClientVersion: "26.3.27"}); err == nil || len(data) != 0 {
		t.Fatal("invalid extension exported")
	}
}
