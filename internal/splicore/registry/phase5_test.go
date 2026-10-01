package registry_test

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"testing"
	"time"
)

func TestVLESSProtocolIsIndependentOfEngine(t *testing.T) {
	p, e, _, err := registry.Phase5()
	if err != nil {
		t.Fatal(err)
	}
	implementations := e.Implementations("vless")
	if len(implementations) != 2 || implementations[0].ID != "native" || implementations[1].ID != "xray" || implementations[1].RuntimeImplemented || implementations[1].Availability != ports.NotCompiled {
		t.Fatal("VLESS multi-engine declaration")
	}
	id := func() identity.ID {
		id, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	settings := []byte(`{"security":"none","flow":"none","transport":"tcp","packet_encoding":"xudp"}`)
	i := access.Inbound{ID: id(), NodeID: id(), Name: "synthetic", Protocol: v.Key(v.Plain), Engine: "xray", Enabled: true, Listeners: []access.Listener{{ID: id(), Transport: "tcp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 12345}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: id(), Endpoint: access.Endpoint{Host: "edge.test", Port: 443}}}, Tags: []string{}, Settings: access.Settings{Schema: 1, Data: settings}, Stamp: identity.NewStamp(time.Now())}
	m, _ := p.Get(i.Protocol)
	if err := m.ValidateInbound(i); err != nil {
		t.Fatal("protocol rejected future engine", err)
	}
	in, err := m.BuildRuntime(context.Background(), ports.RuntimeIntent{Inbound: i})
	if err != nil {
		t.Fatal(err)
	}
	n, _ := e.Get("native")
	if _, err := n.Compile(context.Background(), in); err == nil {
		t.Fatal("native executed xray intent")
	}
	x, _ := e.Get("xray")
	if _, err := x.Compile(context.Background(), in); err == nil {
		t.Fatal("placeholder executed")
	}
	doc := map[string]any{"schema": 1, "engine": "xray", "name": "synthetic", "listener": access.Endpoint{Host: "127.0.0.1", Port: 12345}, "display_endpoint": access.Endpoint{Host: "edge.test", Port: 443}, "settings": json.RawMessage(settings), "users": []any{map[string]any{"account_name": "Alice"}}}
	b, _ := json.Marshal(doc)
	if _, err := p.DecodeCreation(e, "vless", b); err == nil {
		t.Fatal("unavailable engine plan admitted")
	}
	doc["engine"] = "native"
	b, _ = json.Marshal(doc)
	d, err := p.DecodeCreation(e, "vless", b)
	if err != nil || d.Engine != "native" || d.Protocol.Protocol != "vless" {
		t.Fatal("native selection", err)
	}
	for _, engine := range []any{"", nil, "unknown", 123} {
		doc["engine"] = engine
		b, _ = json.Marshal(doc)
		if _, err := p.DecodeCreation(e, "vless", b); err == nil {
			t.Fatal("invalid engine selection")
		}
	}
}
