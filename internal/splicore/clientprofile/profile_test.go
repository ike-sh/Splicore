package clientprofile

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
)

func TestEngineNeutralProfile(t *testing.T) {
	id, _ := identity.NewID()
	p := Profile{ID: id, Schema: 1, Protocol: access.ProtocolKey{Protocol: "vless", WireVersion: "0", FeatureProfile: "base"}, Endpoint: access.Endpoint{Host: "example.com", Port: 443}, Credentials: access.UUIDPayload{UUID: secret.New("00000000-0000-4000-8000-000000000001")}, TLS: TLS{Enabled: true, ServerName: "example.net"}, Options: access.Settings{Schema: 1, Data: json.RawMessage(`{}`)}}
	if p.Validate() != nil {
		t.Fatal("valid profile rejected")
	}
	if _, ok := reflect.TypeOf(p).FieldByName("Engine"); ok {
		t.Fatal("engine leaked into profile contract")
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "00000000") {
		t.Fatal("default profile reveal")
	}
	if p.Endpoint.Host == p.TLS.ServerName {
		t.Fatal("endpoint and SNI conflated")
	}
}
