package native

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"testing"
)

func TestVisionCompilerRejectsUnsupportedBeforeConstruction(t *testing.T) {
	for _, s := range []string{`{"security":"none","flow":"xtls-rprx-vision","transport":"tcp","packet_encoding":"xudp"}`, `{"security":"tls","flow":"xtls-rprx-vision","transport":"tcp","packet_encoding":"xudp","stream_transport":{"kind":"ws"}}`, `{"security":"reality","flow":"xtls-rprx-vision-udp443","transport":"tcp","packet_encoding":"xudp"}`} {
		in := ports.RuntimeIntent{Inbound: access.Inbound{Engine: "native", Settings: access.Settings{Schema: 1, Data: []byte(s)}}}
		p, e := (VLESSCompiler{}).Compile(underlay.WithFactory(context.Background(), underlay.New()), in)
		if p != nil || e == nil {
			t.Fatal("unsupported configuration admitted")
		}
	}
}
