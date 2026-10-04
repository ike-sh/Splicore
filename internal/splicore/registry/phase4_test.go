package registry

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	hm "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	sm "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	tm "github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	"testing"
)

func TestPhase4RegistrationPreservesSnellAndDeferredModules(t *testing.T) {
	p, e, x, err := Phase4()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []access.ProtocolKey{tm.Key(), hm.Key(), sm.Key(5), sm.Key(6)} {
		module, err := p.Get(key)
		if err != nil || module.Metadata().Availability != ports.Compiled || module.Metadata().Qualification != "experimental" {
			t.Fatal("implemented module lost", err)
		}
	}
	for _, key := range []access.ProtocolKey{{Protocol: "vless", WireVersion: "0", FeatureProfile: "base"}} {
		module, err := p.Get(key)
		if err != nil || module.Metadata().Availability != ports.NotCompiled {
			t.Fatal("scope expanded")
		}
	}
	if len(e.Keys()) != 1 {
		t.Fatal("duplicated native engine")
	}
	native, err := e.Get("native")
	if err != nil || native.Metadata().Availability != ports.Compiled {
		t.Fatal("native unavailable")
	}
	for _, format := range []ports.Format{ports.Mihomo, ports.SingBox, ports.Surge} {
		if _, err = x.Get(format); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"snell", "hysteria2", "tuic"} {
		if _, err := p.Creation(id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Creation("vless"); err == nil {
		t.Fatal("deferred command admitted")
	}
	hy, _ := p.Get(hm.Key())
	if kinds := hy.Metadata().CredentialKinds; len(kinds) != 1 || kinds[0] != access.Password {
		t.Fatal("invented username/PSK")
	}
}
