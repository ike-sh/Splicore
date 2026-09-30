package access

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
)

func TestEndpoints(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "example.com", "xn--bcher-kva.example.com"} {
		if (Endpoint{Host: host, Port: 443}).Validate() != nil {
			t.Errorf("valid host rejected: %s", host)
		}
		if _, err := ParseHost(host); err != nil {
			t.Errorf("ParseHost rejected %s", host)
		}
	}
	for _, host := range []string{"999.999.999.999", "256.1.1.1", "https://example.com", "example.com:443", "example.com ", "exam ple.com", "example.com\x00", "example.com\n", "[2001:db8::1]", "2001:db8::1%eth0", "example..com", "-example.com"} {
		if (Endpoint{Host: host, Port: 443}).Validate() == nil {
			t.Errorf("invalid host accepted: %q", host)
		}
	}
	if (Endpoint{Host: "example.com"}).Validate() == nil {
		t.Fatal("port zero accepted")
	}
}

func TestModelsAndCredentialRedaction(t *testing.T) {
	id, _ := identity.NewID()
	stamp := identity.NewStamp(time.Now())
	a := Account{ID: id, Name: "Alice", Status: Active, Enabled: true, Stamp: stamp}
	if a.Validate() != nil {
		t.Fatal("account invalid")
	}
	uuid := secret.New("00000000-0000-4000-8000-000000000001")
	dummy := secret.New("dummy-password")
	for _, p := range []Payload{PSKPayload{dummy}, UUIDPayload{uuid}, UUIDPasswordPayload{uuid, dummy}, UsernamePasswordPayload{secret.New("dummy-user"), dummy}} {
		c := Credential{ID: id, OwnerAccountID: &id, Kind: p.Kind(), Schema: 1, State: "active", Payload: p, Stamp: stamp}
		if c.Validate() != nil {
			t.Fatal("typed credential invalid")
		}
		b, _ := json.Marshal(c)
		for _, s := range []string{string(b), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", p)} {
			if strings.Contains(s, "dummy-password") || strings.Contains(s, uuid.Reveal()) {
				t.Fatal("credential leak")
			}
		}
		c.Kind = "unknown"
		if c.Validate() == nil {
			t.Fatal("kind mismatch accepted")
		}
		c.Kind = p.Kind()
		c.OwnerInboundID = &id
		if c.Validate() == nil {
			t.Fatal("two owners accepted")
		}
	}
	b := Binding{ID: id, AccountID: id, InboundID: id, CredentialID: id, Stamp: stamp}
	if b.Validate() != nil {
		t.Fatal("binding invalid")
	}
	settings := Settings{Schema: 1, Data: json.RawMessage(`{"password":"dummy-password"}`)}
	raw, _ := json.Marshal(settings)
	if strings.Contains(string(raw), "dummy-password") || strings.Contains(fmt.Sprintf("%+v", settings), "dummy-password") {
		t.Fatal("settings leaked")
	}
}

func FuzzEndpoint(f *testing.F) {
	for _, s := range []string{"192.0.2.1", "2001:db8::1", "example.com", "999.999.999.999", "example.com:443", "example.com\n"} {
		f.Add(s, uint16(443))
	}
	f.Fuzz(func(t *testing.T, host string, port uint16) {
		e := Endpoint{host, port}
		if e.Validate() == nil {
			if port == 0 {
				t.Fatal("zero port")
			}
			if _, err := ParseHost(host); err != nil {
				t.Fatal("inconsistent host validation")
			}
		}
	})
}
