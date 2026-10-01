package tuic

import (
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"strings"
	"testing"
	"time"
)

func TestCredentialGenerationValidationAndRedaction(t *testing.T) {
	seen := map[string]bool{}
	owner, _ := identity.NewID()
	for range 32 {
		p, err := GenerateCredential()
		if err != nil {
			t.Fatal(err)
		}
		v := p.(access.UUIDPasswordPayload)
		id, _ := identity.NewID()
		c := access.Credential{ID: id, OwnerAccountID: &owner, Kind: access.UUIDPassword, Schema: 1, State: "active", Payload: v, Stamp: identity.NewStamp(time.Now())}
		if (Module{}).ValidateCredential(c) != nil || seen[v.UUID.Reveal()] || seen[v.Password.Reveal()] {
			t.Fatal("generation")
		}
		seen[v.UUID.Reveal()] = true
		seen[v.Password.Reveal()] = true
		b, _ := json.Marshal(c)
		if strings.Contains(string(b), v.UUID.Reveal()) || strings.Contains(fmt.Sprintf("%+v", c), v.Password.Reveal()) {
			t.Fatal("redaction")
		}
		for _, bad := range []access.UUIDPasswordPayload{{UUID: secret.New("invalid"), Password: v.Password}, {UUID: v.UUID, Password: secret.New("short")}, {UUID: secret.New("00000000-0000-0000-0000-000000000000"), Password: v.Password}} {
			c.Payload = bad
			if (Module{}).ValidateCredential(c) == nil {
				t.Fatal("invalid credential")
			}
		}
	}
}
func TestSettingsBoundaries(t *testing.T) {
	s := Settings{TLS: testkit.TLSForName(t, "tuic.synthetic.test"), Version: 5, CongestionControl: "cubic", UDPRelayMode: "native"}
	b, _ := json.Marshal(s)
	if _, err := Decode(b); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"version", "congestion", "mode", "0rtt", "unknown", "null"} {
		v := s
		switch field {
		case "version":
			v.Version = 4
		case "congestion":
			v.CongestionControl = "bbr"
		case "mode":
			v.UDPRelayMode = "quic"
		case "0rtt":
			v.ZeroRTT = true
		}
		bad, _ := json.Marshal(v)
		if field == "unknown" {
			bad = append(bad[:len(bad)-1], []byte(`,"other":true}`)...)
		}
		if field == "null" {
			bad = []byte(strings.Replace(string(bad), `"zero_rtt_handshake":false`, `"zero_rtt_handshake":null`, 1))
		}
		if _, err := Decode(bad); err == nil {
			t.Fatal(field)
		}
	}
}
func FuzzTUICSettings(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":5}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b) })
}
func FuzzTUICCreation(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"users":[{"uuid":null,"password":123}]}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = (Module{}).DecodeCreation(b) })
}
func FuzzTUICCredential(f *testing.F) {
	f.Add("68f4f564-142b-46b3-8c89-322a37ef1b30", "SyntheticPasswordPhase4")
	f.Fuzz(func(t *testing.T, id, pass string) {
		_ = ValidateUUID(secret.New(id))
		owner, _ := identity.NewID()
		cid, _ := identity.NewID()
		_ = (Module{}).ValidateCredential(access.Credential{ID: cid, OwnerAccountID: &owner, Kind: access.UUIDPassword, Schema: 1, State: "active", Payload: access.UUIDPasswordPayload{UUID: secret.New(id), Password: secret.New(pass)}, Stamp: identity.NewStamp(time.Now())})
	})
}
