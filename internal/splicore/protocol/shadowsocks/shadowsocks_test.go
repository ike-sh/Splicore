package shadowsocks

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
)

func TestMethodCredentialAndCreationValidation(t *testing.T) {
	for _, m := range Methods() {
		p, e := Generate(m.Name)
		if e != nil || ValidateMaterial(m.Name, p, false) != nil {
			t.Fatal("generated credential", m.Name, e)
		}
		if m.Edition == "2022" {
			for _, size := range []int{0, m.KeySize - 1, m.KeySize + 1, 64} {
				if _, e = DecodeKeys(m.Name, base64.StdEncoding.EncodeToString(make([]byte, size)), false); e == nil {
					t.Fatal("wrong size accepted", size)
				}
			}
			if _, e = DecodeKeys(m.Name, Material(p)+"\n", false); e == nil {
				t.Fatal("non-canonical base64")
			}
		}
	}
	for _, raw := range []string{`{"method":"none"}`, `{"method":"aes-256-gcm","method":"aes-128-gcm"}`, `{"method":"aes-256-gcm","udp":null}`, `{"method":"aes-256-gcm","multi_user":true}`, `{"method":"2022-blake3-chacha20-poly1305","multi_user":true}`, `{"method":"aes-256-gcm","password":"hidden"}`} {
		if _, e := Decode([]byte(raw)); e == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	for _, m := range Methods() {
		settings := map[string]any{"method": m.Name}
		users := []any{map[string]any{"account_name": "Alice"}}
		if m.Identity {
			settings["multi_user"] = true
			users = append(users, map[string]any{"account_name": "Bob"})
		}
		raw, _ := json.Marshal(map[string]any{"schema": 1, "name": "SS", "listener": access.Endpoint{Host: "127.0.0.1", Port: 30000}, "display_endpoint": access.Endpoint{Host: "localhost", Port: 30000}, "settings": settings, "users": users})
		d, e := (Module{}).DecodeCreation(raw)
		if e != nil {
			t.Fatal(e)
		}
		d, e = (Module{}).MaterializeCreation(d)
		if e != nil {
			t.Fatal(e)
		}
		for _, u := range d.Users {
			if ValidateMaterial(m.Name, u.Payload, false) != nil {
				t.Fatal("materialization")
			}
		}
		if strings.Contains(fmt.Sprintf("%+v", d), Material(d.Users[0].Payload)) {
			t.Fatal("draft formatting leaked")
		}
	}
}
func TestShadowsocksURILossless(t *testing.T) {
	for _, m := range Methods() {
		p, e := Generate(m.Name)
		if e != nil {
			t.Fatal(e)
		}
		if m.Identity {
			p = access.PSKPayload{Key: secret.New(Material(p) + ":" + Material(p))}
		}
		for _, host := range []string{"127.0.0.1", "::1", "synthetic.example"} {
			v := URI{Name: "Synthetic name + #", Method: m.Name, Endpoint: access.Endpoint{Host: host, Port: 443}, Credential: p}
			raw, e := ExportURI(v)
			if e != nil {
				t.Fatal(e)
			}
			got, e := ParseURI(raw)
			if e != nil || got.Method != v.Method || got.Name != v.Name || got.Endpoint != v.Endpoint || Material(got.Credential) != Material(p) {
				t.Fatal("URI roundtrip", m.Name, e)
			}
			if m.Edition == "2022" && !strings.HasPrefix(raw, "ss://2022-") {
				t.Fatal("SS2022 userinfo was base64 encoded")
			}
		}
	}
	legacy := "ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-256-gcm:synthetic:password@localhost:443")) + "#Legacy"
	if v, e := ParseURI(legacy); e != nil || Material(v.Credential) != "synthetic:password" {
		t.Fatal("legacy", e)
	}
	for _, raw := range []string{"ss://", "ss://aes-256-gcm:p@localhost:0", "ss://aes-256-gcm:p@localhost:443/?plugin=obfs", "ss://aes-256-gcm:p@localhost:443?udp=false", "ss2022://anything", "ss://aes-256-gcm:p@localhost:443#bad name"} {
		if _, e := ParseURI(raw); e == nil {
			t.Fatal("ambiguous URI accepted")
		}
	}
	for _, password := range []string{"bad\tcredential", "bad\x1bcredential", "bad\ncredential"} {
		encoded := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:"+password)) + "@localhost:443"
		if _, e := ParseURI(encoded); e == nil {
			t.Fatal("decoded credential control character accepted")
		}
		v := URI{Name: "Synthetic", Method: "aes-128-gcm", Endpoint: access.Endpoint{Host: "localhost", Port: 443}, Credential: access.PasswordPayload{Password: secret.New(password)}}
		if _, e := ExportURI(v); e == nil {
			t.Fatal("unimportable credential exported")
		}
	}
}
func FuzzShadowsocksURI(f *testing.F) {
	f.Add("ss://YWVzLTI1Ni1nY206c3ludGhldGlj@localhost:443#Synthetic")
	f.Add("ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@127.0.0.1:443")
	f.Fuzz(func(t *testing.T, raw string) {
		v, e := ParseURI(raw)
		if e != nil {
			return
		}
		out, e := ExportURI(v)
		if e != nil {
			t.Fatal(e)
		}
		other, e := ParseURI(out)
		if e != nil || Material(other.Credential) != Material(v.Credential) || other.Endpoint != v.Endpoint || other.Method != v.Method {
			t.Fatal("lossy accepted URI")
		}
		if !bytes.Equal([]byte(other.Name), []byte(v.Name)) {
			t.Fatal("name roundtrip")
		}
	})
}
