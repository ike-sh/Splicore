package registry_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/engine/xray"
	"github.com/sagernet/sing-box/internal/splicore/registry"
)

func TestPhase6PlacementHasNoFallback(t *testing.T) {
	p, e, _, err := registry.Phase6(xray.New(xray.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	b := []byte(`{"schema":1,"name":"synthetic","listener":{"host":"127.0.0.1","port":12345},"display_endpoint":{"host":"edge.synthetic.test","port":443},"settings":{"security":"none","flow":"none","transport":"tcp","packet_encoding":"xudp"},"users":[{"account_name":"Alice"}]}`)
	var d map[string]any
	_ = json.Unmarshal(b, &d)
	d["engine"] = "xray"
	b, _ = json.Marshal(d)
	draft, err := p.DecodeCreation(e, "vless", b)
	if err != nil || draft.Engine != "xray" || draft.Protocol.Protocol != "vless" {
		t.Fatal("duality", err)
	}
	snell, err := os.ReadFile("../../../tests/fixtures/nobrand/snell.json")
	if err != nil {
		t.Fatal(err)
	}
	var command map[string]json.RawMessage
	_ = json.Unmarshal(snell, &command)
	command["engine"] = json.RawMessage(`"xray"`)
	snell, _ = json.Marshal(command)
	_, err = p.DecodeCreation(e, "snell", snell)
	var de *identity.Error
	if !errors.As(err, &de) || de.Code != identity.UnsupportedEngineForProtocol {
		t.Fatal("illegal pair must be typed", err)
	}
}
