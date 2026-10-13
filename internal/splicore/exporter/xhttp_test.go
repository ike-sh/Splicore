package exporter

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"testing"
)

func TestXHTTPProjectionRetainsEveryControl(t *testing.T) {
	c := cfg.Config{Kind: "xhttp", Host: "authority.test", Path: "/path?x=1", Headers: map[string]string{"X-Custom": "value"}, XHTTP: &cfg.XHTTP{Mode: "packet-up", Padding: cfg.Range{100, 200}, PaddingObfs: true, PaddingPlacement: "cookie", PaddingMethod: "tokenish", Method: "GET", SessionPlacement: "header", SequencePlacement: "query", DataPlacement: "header", XMUX: &cfg.XMUX{MaxConnections: cfg.Range{1, 2}, Requests: cfg.Range{20, 30}}}}
	p, e := xhttpProjection(c)
	if e != nil {
		t.Fatal(e)
	}
	if p["path"] != c.Path || p["host"] != c.Host || p["mode"] != "packet-up" || p["uplinkHTTPMethod"] != "GET" || p["xPaddingMethod"] != "tokenish" || p["sessionIDPlacement"] != "header" || p["seqPlacement"] != "query" || p["uplinkDataPlacement"] != "header" {
		t.Fatal("lossy projection")
	}
	b, _ := json.Marshal(p)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	delete(fields, "path")
	delete(fields, "host")
	delete(fields, "headers")
	b, _ = json.Marshal(fields)
	var x cfg.XHTTP
	if json.Unmarshal(b, &x) != nil || x.Validate() != nil {
		t.Fatal("export options not roundtrippable")
	}
}

func TestXHTTPH1SecurityProjectionPreservesALPN(t *testing.T) {
	s := xraySecurity("tls", access.ClientTLS{ServerName: "core.test", ALPN: []string{"http/1.1"}, Trust: "system"})
	v := s["tlsSettings"].(map[string]any)
	if v["fingerprint"] != "unsafe" || v["allowInsecure"] != false {
		t.Fatal("H1 TLS selection or verification changed")
	}
}
