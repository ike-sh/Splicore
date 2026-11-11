package mieru

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"strings"
	"testing"
)

func TestCanonicalBoundsAndCredentialGeneration(t *testing.T) {
	for _, data := range []string{`null`, `{}`, `{"transport":"quic"}`, `{"transport":"tcp","mtu":null}`, `{"transport":"tcp","mtu":1501}`, `{"transport":"udp","mtu":1279}`, `{"transport":"tcp","multiplex":"unknown"}`, `{"transport":"tcp","password":"forbidden"}`, `{"transport":"tcp","transport":"udp"}`} {
		if _, e := Decode([]byte(data)); e == nil {
			t.Fatal("invalid canonical contract accepted")
		}
	}
	s, e := Decode([]byte(`{"transport":"tcp"}`))
	if e != nil || s.MTU != 1500 || s.Multiplex != "default" {
		t.Fatal("default canonical contract", e)
	}
	generated, e := (Module{}).GenerateCreationCredential(access.UsernamePasswordPayload{})
	if e != nil {
		t.Fatal(e)
	}
	p := generated.(access.UsernamePasswordPayload)
	if ValidateUsername(p.Username) != nil || ValidatePassword(p.Password) != nil {
		t.Fatal("generation invalid")
	}
	for _, p := range []access.UsernamePasswordPayload{{Username: secret.New("Alice"), Password: secret.New(strings.Repeat("x", 65))}, {Username: secret.New("a b"), Password: secret.New(strings.Repeat("x", 32))}} {
		if _, e := (Module{}).GenerateCreationCredential(p); e == nil {
			t.Fatal("invalid credential accepted")
		}
	}
}
func FuzzCanonicalCreation(f *testing.F) {
	f.Add([]byte(`{"schema":1,"name":"synthetic","listener":{"host":"127.0.0.1","port":12345},"display_endpoint":{"host":"localhost","port":12345},"settings":{"transport":"tcp"},"users":[{"account_name":"Alice"}]}`))
	f.Add([]byte(`{"settings":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, e := (Module{}).DecodeCreation(data)
		if e != nil {
			return
		}
		s, e := Decode(d.Settings)
		if e != nil {
			t.Fatal(e)
		}
		encoded, _ := json.Marshal(s)
		again, e := Decode(encoded)
		if e != nil || again != s || d.Protocol != Key() || d.Transport != s.Transport {
			t.Fatal("canonical round trip or protocol mapping changed")
		}
		for _, u := range d.Users {
			p, ok := u.Payload.(access.UsernamePasswordPayload)
			if !ok {
				t.Fatal("credential kind changed")
			}
			if !p.Username.Empty() && (ValidateUsername(p.Username) != nil || ValidatePassword(p.Password) != nil) {
				t.Fatal("invalid imported credentials")
			}
		}
	})
}
