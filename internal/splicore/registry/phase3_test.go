package registry_test

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	hm "github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	sm "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/registry/testfixture"
	"testing"
)

func TestPhase3RegistrationPreservesSnellAndDeferredModules(t *testing.T) {
	p, e, x, err := testfixture.Phase3()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []access.ProtocolKey{hm.Key(), sm.Key(5), sm.Key(6)} {
		module, err := p.Get(key)
		if err != nil || module.Metadata().Availability != ports.Compiled || module.Metadata().Qualification != "experimental" {
			t.Fatal("implemented module lost", err)
		}
	}
	for _, key := range []access.ProtocolKey{{Protocol: "tuic", WireVersion: "5", FeatureProfile: "base"}, {Protocol: "vless", WireVersion: "0", FeatureProfile: "base"}} {
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
	hy, _ := p.Get(hm.Key())
	if kinds := hy.Metadata().CredentialKinds; len(kinds) != 1 || kinds[0] != access.Password {
		t.Fatal("invented username/PSK")
	}
}
