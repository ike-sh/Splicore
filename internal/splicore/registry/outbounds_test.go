package registry_test

import (
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	. "github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/registry/testfixture"
	"testing"
)

func TestClientOutboundRegistryExactPairsAndRoles(t *testing.T) {
	r, err := NewOutbounds(native.SnellOutboundFactory{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Get("snell", "native"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"snell", "xray"}, {"vless", "native"}, {"direct", "native"}, {"missing", "native"}} {
		if _, err = r.Get(pair[0], pair[1]); err == nil {
			t.Fatal("unsupported pair accepted", pair)
		}
	}
	if _, err = NewOutbounds(native.SnellOutboundFactory{}, native.SnellOutboundFactory{}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err = NewOutbounds(nil); err == nil {
		t.Fatal("nil accepted")
	}
	p, _, _, _ := testfixture.Phase2()
	for _, key := range p.Keys() {
		m, _ := p.Get(key)
		roles := m.Metadata().Roles
		expected := key.Protocol == "snell"
		if roles.Inbound != expected || roles.Outbound != expected {
			t.Fatal("Snell roles", roles)
		}
	}
	caps := r.Capabilities()
	caps[0].Protocol = "tampered"
	if _, err = r.Get("snell", "native"); err != nil || r.Capabilities()[0].Protocol != "snell" {
		t.Fatal("registry alias")
	}
}
