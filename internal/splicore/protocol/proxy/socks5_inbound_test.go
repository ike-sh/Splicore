package proxy

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func TestManagedSOCKS5CreationRequiresAuthentication(t *testing.T) {
	module := SOCKS5Inbound{}
	document := func(settings, users string) json.RawMessage {
		return json.RawMessage(`{"schema":1,"name":"test-proxy","listener":{"host":"127.0.0.1","port":18080},
			"display_endpoint":{"host":"proxy.example","port":1080},"settings":` + settings + `,"users":` + users + `}`)
	}
	const settings = `{"auth":true,"udp":false}`
	const generated = `[{"account_name":"test-user","username":"alice"}]`
	for _, doc := range []json.RawMessage{
		document(`{"auth":false}`, generated),
		document(`{"auth":true,"udp":true}`, generated),
		document(settings, `[]`),
		document(settings, `[{"account_name":"test-user","username":""}]`),
		document(settings, `[{"account_name":"test-user","username":"alice","password":""}]`),
		document(settings, `[{"account_name":"test-user","username":"alice","password":"xxxxxxxxxxxxxxxx"}]`),
		document(settings, `[{"account_name":"test-user","username":"alice","enabled":false}]`),
		document(settings, `[{"account_name":"first","username":"alice"},{"account_name":"second","username":"alice","enabled":false}]`),
	} {
		if _, err := module.DecodeCreation(doc); err == nil {
			t.Fatal("managed creation accepted invalid authentication settings")
		}
	}
	draft, err := module.DecodeCreation(document(settings, generated))
	if err != nil {
		t.Fatal(err)
	}
	first, err := module.GenerateCreationCredential(draft.Users[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := module.GenerateCreationCredential(draft.Users[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Pair(access.Credential{Payload: first})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Pair(access.Credential{Payload: second})
	if err != nil {
		t.Fatal(err)
	}
	if a.Username != "alice" || len(a.Password) < 32 || a.Password == b.Password {
		t.Fatal("generated credentials are missing, short, or reused")
	}
	remote := bytes.ReplaceAll(document(settings, generated), []byte("127.0.0.1"), []byte("0.0.0.0"))
	if _, err := module.DecodeCreation(remote); err == nil {
		t.Fatal("non-loopback cleartext listener was accepted without opt-in")
	}
	remote = bytes.ReplaceAll(remote, []byte(`"udp":false`), []byte(`"allow_cleartext_remote":true`))
	if _, err := module.DecodeCreation(remote); err != nil {
		t.Fatal("explicit non-loopback listener with display endpoint was rejected", err)
	}
}
