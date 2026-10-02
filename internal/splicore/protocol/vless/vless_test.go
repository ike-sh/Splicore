package vless

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"strings"
	"testing"
)

func realitySettings(t *testing.T) Settings {
	t.Helper()
	_, pub, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	return Settings{Security: Reality, Flow: NoFlow, Transport: "tcp", PacketEncoding: "xudp", Reality: &RealitySettings{PublicKey: pub, ServerName: "target.synthetic.test", Target: access.Endpoint{Host: "target.synthetic.test", Port: 443}, ShortIDs: []ShortID{"0123", "abcd"}}}
}
func TestKeysShortIDsAndSettings(t *testing.T) {
	p, pub, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DerivePublicKey(p); err != nil || got != pub {
		t.Fatal("derivation")
	}
	if string(pub) == p.Material.Reveal() {
		t.Fatal("private/public confused")
	}
	serialized, _ := json.Marshal(p)
	if strings.Contains(string(serialized), p.Material.Reveal()) || strings.Contains(fmt.Sprintf("%+v %#v", p, p), p.Material.Reveal()) {
		t.Fatal("key formatting leak")
	}
	for _, value := range []string{"", "=", strings.Repeat("a", 42), base64.RawStdEncoding.EncodeToString(make([]byte, 32))} {
		key := access.PrivateKeyPayload{Algorithm: "x25519", Material: secret.New(value)}
		if value == base64.RawURLEncoding.EncodeToString(make([]byte, 32)) {
			continue
		}
		if _, err := DerivePublicKey(key); err == nil {
			t.Fatal("bad private key accepted")
		}
	}
	for _, sid := range []ShortID{"", "ab", "ABCDEF", "0123456789abcdef"} {
		if _, err := ParseShortID(sid); err != nil {
			t.Fatal("baseline valid short ID rejected")
		}
	}
	for _, sid := range []ShortID{"a", "xyz0", "0123456789abcdef00", "ab\n"} {
		if _, err := ParseShortID(sid); err == nil {
			t.Fatal("invalid short ID")
		}
	}
	s := realitySettings(t)
	b, _ := json.Marshal(s)
	if _, err := Decode(b); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Settings){
		func(s *Settings) { s.Flow = "arbitrary" }, func(s *Settings) { s.Transport = "ws" }, func(s *Settings) { s.PacketEncoding = "packetaddr" },
		func(s *Settings) { s.Reality.PublicKey = "invalid" }, func(s *Settings) { s.Reality.ShortIDs = []ShortID{"ab", "ab00"} },
		func(s *Settings) { s.Reality.Target.Host = "bad:443" }, func(s *Settings) { s.Reality.Target.Port = 0 }, func(s *Settings) { s.Reality.ServerName = "127.0.0.1" },
	}
	for _, mutate := range mutations {
		s := realitySettings(t)
		mutate(&s)
		b, _ := json.Marshal(s)
		if _, err := Decode(b); err == nil {
			t.Fatal("invalid settings accepted")
		}
	}
	s.Reality.ShortIDs = nil
	b, _ = json.Marshal(s)
	got, err := Decode(b)
	if err != nil || len(got.Reality.ShortIDs) != 1 || got.Reality.ShortIDs[0] != "" {
		t.Fatal("zero short ID semantics")
	}
	if _, err := Decode([]byte(`{"security":"none","security":"reality"}`)); err == nil {
		t.Fatal("duplicate field")
	}
	if _, err := DecodeClientOptions([]byte(`{"security":"reality","flow":"none","packet_encoding":"xudp","private_key":"hidden"}`)); err == nil {
		t.Fatal("client private extension admitted")
	}
}
func TestUUIDGenerationValidationAndCapabilities(t *testing.T) {
	m := Module{Security: Reality}
	p, err := m.GenerateCreationCredential(access.UUIDPayload{})
	if err != nil {
		t.Fatal(err)
	}
	value := p.(access.UUIDPayload).UUID
	if ValidateUUID(value) != nil || !strings.Contains(fmt.Sprint(value), "REDACTED") {
		t.Fatal("generated UUID")
	}
	for _, s := range []string{"", "00000000-0000-0000-0000-000000000000", "not-a-uuid", "68f4f564142b46b38c89322a37ef1b30", "{68f4f564-142b-46b3-8c89-322a37ef1b30}"} {
		if ValidateUUID(secret.New(s)) == nil {
			t.Fatal("invalid UUID admitted")
		}
	}
	if ValidateUUID(secret.New(strings.ToUpper(value.Reveal()))) != nil {
		t.Fatal("canonical upper case rejected")
	}
	c := m.Capabilities(ports.CapabilityContext{Engine: "native"})
	if c.Transport.UDPTransport || c.Mutation.Users == ports.Hot || c.Mutation.HotReload {
		t.Fatal("capability overclaim")
	}
	if c.Security.Reality != RealityCompiled {
		t.Fatal("build availability mismatch")
	}
	x := m.Capabilities(ports.CapabilityContext{Engine: "xray"})
	if x.Transport.TCP != RealityCompiled || x.Identity.PerUserStats || x.Security.Vision {
		t.Fatal("external placement capability mismatch")
	}
}

func TestCreationSecretAndValidationBoundaries(t *testing.T) {
	if !RealityCompiled {
		t.Skip("REALITY requires with_utls")
	}
	key, pub, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	s := realitySettings(t)
	s.Reality.PublicKey = ""
	doc := map[string]any{"schema": 1, "name": "synthetic", "listener": access.Endpoint{Host: "127.0.0.1", Port: 12345}, "display_endpoint": access.Endpoint{Host: "edge.test", Port: 443}, "settings": s, "users": []any{map[string]any{"account_name": "Alice"}, map[string]any{"account_name": "Bob"}}}
	raw, _ := json.Marshal(doc)
	d, err := (Module{}).DecodeCreation(raw)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := (Module{}).MaterializeCreation(d)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := Decode(materialized.Settings)
	if err != nil || len(materialized.ServerPayloads) != 1 {
		t.Fatal("generated key preparation")
	}
	generated := materialized.ServerPayloads[0].(access.PrivateKeyPayload)
	actual, _ := DerivePublicKey(generated)
	if committed.Reality.PublicKey != actual || strings.Contains(string(materialized.Settings), generated.Material.Reveal()) {
		t.Fatal("generated key/public separation")
	}
	doc["server_secret"] = map[string]any{"private_key": key.Material.Reveal()}
	s.Reality.PublicKey = pub
	doc["settings"] = s
	raw, _ = json.Marshal(doc)
	if _, err := (Module{}).DecodeCreation(raw); err != nil {
		t.Fatal("supplied pair", err)
	}
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { d["server_secret"] = map[string]any{"private_key": "bad"} },
		func(d map[string]any) { d["server_secret"] = map[string]any{"private_key": nil} },
		func(d map[string]any) { d["server_secret"] = nil },
		func(d map[string]any) {
			d["settings"].(map[string]any)["reality"].(map[string]any)["short_ids"] = []string{"a"}
		},
		func(d map[string]any) {
			d["settings"].(map[string]any)["reality"].(map[string]any)["target"] = map[string]any{"host": "bad:443", "port": 443}
		},
		func(d map[string]any) { d["settings"].(map[string]any)["private_key"] = "hidden" },
		func(d map[string]any) { d["users"].([]any)[0].(map[string]any)["uuid"] = "invalid" },
		func(d map[string]any) {
			for _, u := range d["users"].([]any) {
				u.(map[string]any)["uuid"] = "00000000-0000-4000-8000-000000000001"
			}
		},
	} {
		var copy map[string]any
		_ = json.Unmarshal(raw, &copy)
		mutate(copy)
		b, _ := json.Marshal(copy)
		if _, err := (Module{}).DecodeCreation(b); err == nil {
			t.Fatal("invalid creation boundary admitted")
		}
	}
}
func FuzzSettings(f *testing.F) {
	f.Add([]byte(`{"security":"none","flow":"none","transport":"tcp","packet_encoding":"xudp"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := Decode(b)
		if err == nil {
			normalized, _ := json.Marshal(s)
			if _, err := Decode(normalized); err != nil {
				t.Fatal("normalization changed validity")
			}
		}
	})
}
func FuzzUUID(f *testing.F) {
	f.Add("00000000-0000-4000-8000-000000000001")
	f.Fuzz(func(t *testing.T, s string) { _ = ValidateUUID(secret.New(s)) })
}
func FuzzShortID(f *testing.F) {
	f.Add("")
	f.Add("ab00")
	f.Fuzz(func(t *testing.T, s string) { _, _ = ParseShortID(ShortID(s)) })
}
func FuzzTarget(f *testing.F) {
	f.Add("target.test", uint16(443))
	f.Fuzz(func(t *testing.T, h string, p uint16) { _ = (access.Endpoint{Host: h, Port: p}).Validate() })
}
