package exporter

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
)

func TestMKCPProjectionRejectsLossyFormats(t *testing.T) {
	m := cfg.DefaultMKCP()
	m.MTU = 576
	m.CWNDMultiplier = 3
	p := clientprofile.Profile{Protocol: vl.Key(vl.Plain), Transport: cfg.Config{Kind: "mkcp", MKCP: &m}}
	for _, format := range []ports.Format{ports.SingBox, ports.Mihomo, ports.URI} {
		n := map[string]any{}
		if streamProjection(p, format, n) == nil || len(n) != 0 {
			t.Fatal("lossy export silently changed transport", format, n)
		}
	}
	n := map[string]any{"streamSettings": map[string]any{}}
	if e := streamProjection(p, ports.Xray, n); e != nil {
		t.Fatal(e)
	}
	stream := n["streamSettings"].(map[string]any)
	if stream["network"] != "kcp" {
		t.Fatal("reference network name")
	}
	b, _ := json.Marshal(stream["kcpSettings"])
	var got cfg.MKCP
	if json.Unmarshal(b, &got) != nil || got != m {
		t.Fatal("tuning discarded")
	}
	q := url.Values{}
	if p.Transport.PutQuery(q) == nil {
		t.Fatal("URI tuning loss accepted")
	}
	if _, e := cfg.Query(url.Values{"type": []string{"mkcp"}}); e == nil {
		t.Fatal("unqualified URI imported")
	}
	id, _ := identity.NewID()
	options, _ := json.Marshal(vl.ClientOptions{Security: vl.Plain, Flow: vl.NoFlow, PacketEncoding: "xudp"})
	p.ID = id
	p.Schema = 1
	p.Endpoint = access.Endpoint{Host: "localhost", Port: 8443}
	p.Credentials = access.UUIDPayload{UUID: secret.New(string(id))}
	p.UDPPayload = true
	p.Options = access.Settings{Schema: 1, Data: options}
	exported, e := (VLESS{Target: ports.Xray}).Export(context.Background(), p, ports.ExportTarget{Format: ports.Xray, ClientVersion: "26.10.10"})
	if e != nil {
		t.Fatal("modern qualified Xray export", e)
	}
	var projection struct {
		Stream struct {
			Network string   `json:"network"`
			MKCP    cfg.MKCP `json:"kcpSettings"`
		} `json:"streamSettings"`
	}
	if json.Unmarshal(exported, &projection) != nil || projection.Stream.Network != "kcp" || projection.Stream.MKCP != m {
		t.Fatal("actual exporter lost mKCP tuning")
	}
}
