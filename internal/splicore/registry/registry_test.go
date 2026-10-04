package registry

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
)

func hasCode(err error, code identity.Code) bool {
	var e *identity.Error
	return errors.As(err, &e) && e.Code == code
}

func TestRegistries(t *testing.T) {
	p, e, x, err := Foundation()
	if err != nil {
		t.Fatal(err)
	}
	keys := p.Keys()
	for i := 1; i < len(keys); i++ {
		if keys[i-1].String() >= keys[i].String() {
			t.Fatal("order unstable")
		}
	}
	vless := access.ProtocolKey{Protocol: "vless", WireVersion: "0", FeatureProfile: "base"}
	entry, err := p.Get(vless)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewProtocols(entry, entry); !hasCode(err, identity.Duplicate) {
		t.Fatal("duplicate protocol accepted")
	}
	if _, err = p.Get(access.ProtocolKey{Protocol: "unknown"}); !hasCode(err, identity.NotFound) {
		t.Fatal("unknown not typed")
	}
	bad := ProtocolPlaceholder{Info: entry.Metadata()}
	bad.Info.ABI = 2
	if _, err = NewProtocols(bad); !hasCode(err, identity.Invalid) {
		t.Fatal("unknown ABI accepted")
	}
	metadata := entry.Metadata()
	metadata.CredentialKinds[0] = "changed"
	if entry.Metadata().CredentialKinds[0] != access.UUID {
		t.Fatal("metadata mutable")
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				if _, err := p.Get(vless); err != nil {
					t.Error(err)
				}
				p.Keys()
				e.Keys()
				x.Keys()
			}
		})
	}
	wg.Wait()
	for _, id := range []string{"native"} {
		engine, err := e.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		intent := ports.RuntimeIntent{Inbound: access.Inbound{Protocol: vless, Engine: id}}
		if !hasCode(engine.Supports(intent), identity.NotImplemented) {
			t.Fatal("placeholder claims runtime")
		}
		if runtime, err := engine.Compile(context.Background(), intent); runtime != nil || !hasCode(err, identity.NotImplemented) {
			t.Fatal("fake runtime")
		}
		if _, err = NewEngines(engine, engine); !hasCode(err, identity.Duplicate) {
			t.Fatal("duplicate engine")
		}
	}
	for _, format := range x.Keys() {
		exporter, _ := x.Get(format)
		if out, err := exporter.Export(context.Background(), clientprofile.Profile{}, ports.ExportTarget{Format: format}); out != nil || !hasCode(err, identity.NotImplemented) {
			t.Fatal("fake client config")
		}
		if _, err = NewExporters(exporter, exporter); !hasCode(err, identity.Duplicate) {
			t.Fatal("duplicate exporter")
		}
	}
	for _, model := range []any{access.Account{}, access.Binding{}, clientprofile.Profile{}} {
		if _, ok := reflect.TypeOf(model).FieldByName("Engine"); ok {
			t.Fatal("engine coupled to public model")
		}
	}
}
