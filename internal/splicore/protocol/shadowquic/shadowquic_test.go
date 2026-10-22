package shadowquic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
)

func TestStrictConfigurationAndSNI(t *testing.T) {
	good := `{"server_name":"cover.test","camouflage_endpoint":{"host":"127.0.0.1","port":443}}`
	if _, e := Decode([]byte(good)); e != nil {
		t.Fatal(e)
	}
	for _, b := range []string{`{}`, `null`, strings.Replace(good, `"cover.test"`, `"bad name"`, 1), strings.Replace(good, `"cover.test"`, `"127.0.0.1"`, 1), strings.Replace(good, `"cover.test"`, `"https://cover.test"`, 1), strings.TrimSuffix(good, "}") + `,"max_streams":null}`, strings.TrimSuffix(good, "}") + `,"max_streams":1,"max_streams":2}`, strings.TrimSuffix(good, "}") + `,"Server_Name":"cover.test"}`} {
		if _, e := Decode([]byte(b)); e == nil {
			t.Fatal("invalid accepted", b)
		}
	}
	for _, b := range []string{`{"max_connections":1}`, `{"over_stream":true}`, `{"zero_rtt":true}`, `{"max_streams":null}`} {
		if _, e := DecodeClient([]byte(b)); e == nil {
			t.Fatal(b)
		}
	}
	p := access.UsernamePasswordPayload{Username: secret.New("auth-user"), Password: secret.New("synthetic-password")}
	if _, e := Pair(p); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(fmt.Sprintf("%+v", p), "synthetic-password") {
		t.Fatal("secret formatting")
	}
	doc := []byte(`{"schema":1,"name":"ShadowQUIC","listener":{"host":"127.0.0.1","port":443},"display_endpoint":{"host":"public.test","port":443},"settings":` + good + `,"users":[{"account_name":"Display only","username":"auth-user","password":"synthetic-password"}]}`)
	d, e := (Module{}).DecodeCreation(doc)
	if e != nil || len(d.Users) != 1 {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(d.Settings)
	if bytes.Contains(raw, []byte("synthetic-password")) {
		t.Fatal("settings secret")
	}
	bad := bytes.Replace(doc, []byte(`"auth-user"`), []byte(`"bad\nuser"`), 1)
	if _, e = (Module{}).DecodeCreation(bad); e == nil {
		t.Fatal("control username")
	}
}
