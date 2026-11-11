package exporter_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func TestVisionQualifiedURIAndUnsupportedExporterTargets(t *testing.T) {
	p, _ := vlessProfile(t, "edge.synthetic.test")
	uri, err := (exporter.VLESS{Target: ports.URI}).Export(context.Background(), p, ports.ExportTarget{Format: ports.URI})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(uri), "flow=") {
		t.Fatal("non-Vision URI emitted flow")
	}
	p.Options.Data = []byte(`{"security":"reality","flow":"xtls-rprx-vision","packet_encoding":"xudp"}`)
	p.UDPPayload = false
	for _, target := range []ports.ExportTarget{{Format: ports.Mihomo, ClientVersion: "1.19.30"}, {Format: ports.SingBox, ClientVersion: "1.14.1"}} {
		e := exporter.VLESS{Target: target.Format}
		output, err := e.Export(context.Background(), p, target)
		var typed *identity.Error
		if len(output) != 0 || !errors.As(err, &typed) || typed.Code != identity.UnsupportedExport {
			t.Fatal("Vision export was not rejected")
		}
		if _, err := e.Describe(p); err == nil {
			t.Fatal("Vision export description accepted")
		}
	}
	input := strings.Replace(string(uri), "#", "&flow=xtls-rprx-vision#", 1)
	if parsed, err := exporter.ParseVLESSURI(input); err != nil || parsed.Flow != "xtls-rprx-vision" {
		t.Fatal("Vision URI rejected", err)
	}
	output, err := (exporter.VLESS{Target: ports.URI}).Export(context.Background(), p, ports.ExportTarget{Format: ports.URI})
	if err != nil || !strings.Contains(string(output), "flow=xtls-rprx-vision") {
		t.Fatal("flow lost", err)
	}
}
