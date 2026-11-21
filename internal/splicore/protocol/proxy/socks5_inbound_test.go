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
		document(`{"auth":false,"udp":true}`, generated),
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

func TestManagedSOCKS5UDPRelaySettings(t *testing.T) {
	for _, row := range []struct {
		name, listener, settings string
		listen, advertise        string
		min, max                 uint16
		enabled, valid           bool
	}{
		{"legacy TCP", "127.0.0.1", `{"auth":true}`, "", "", 0, 0, false, true},
		{"loopback dynamic", "127.0.0.1", `{"auth":true,"udp":true}`, "127.0.0.1", "127.0.0.1", 0, 0, true, true},
		{"IPv6 dynamic", "::1", `{"auth":true,"udp":true}`, "::1", "::1", 0, 0, true, true},
		{"public", "0.0.0.0", `{"auth":true,"udp":true,"allow_cleartext_remote":true,"udp_relay":{"advertise":"proxy.example","port_min":22001,"port_max":22004}}`, "0.0.0.0", "proxy.example", 22001, 22004, true, true},
		{"disabled with relay", "127.0.0.1", `{"auth":true,"udp_relay":{}}`, "", "", 0, 0, false, false},
		{"public without port range", "0.0.0.0", `{"auth":true,"udp":true,"allow_cleartext_remote":true,"udp_relay":{"advertise":"proxy.example"}}`, "", "", 0, 0, false, false},
		{"unspecified advertisement", "0.0.0.0", `{"auth":true,"udp":true,"allow_cleartext_remote":true,"udp_relay":{"advertise":"0.0.0.0","port_min":22001,"port_max":22004}}`, "", "", 0, 0, false, false},
		{"remote relay on local control", "::1", `{"auth":true,"udp":true,"allow_cleartext_remote":true,"udp_relay":{"listen":"::","advertise":"proxy.example","port_min":22001,"port_max":22004}}`, "", "", 0, 0, false, false},
		{"wrong source family", "127.0.0.1", `{"auth":true,"udp":true,"udp_relay":{"listen":"::1"}}`, "", "", 0, 0, false, false},
		{"reversed range", "127.0.0.1", `{"auth":true,"udp":true,"udp_relay":{"port_min":22004,"port_max":22001}}`, "", "", 0, 0, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			in := access.Inbound{Settings: access.Settings{Data: json.RawMessage(row.settings)}}
			in.Listeners = append(in.Listeners, access.Listener{Endpoint: access.Endpoint{Host: row.listener, Port: 1080}})
			relay, enabled, err := (SOCKS5Inbound{}).UDPRelay(in)
			if (err == nil) != row.valid || enabled != row.enabled {
				t.Fatalf("relay setting validity = %t, enabled = %t", err == nil, enabled)
			}
			if relay != (SOCKS5UDPRelay{row.listen, row.advertise, row.min, row.max}) {
				t.Fatalf("unexpected relay settings: %+v", relay)
			}
		})
	}
}
