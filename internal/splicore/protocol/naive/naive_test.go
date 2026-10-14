package naive_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/naive"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func TestNaiveManagedOwnershipAndProfile(t *testing.T) {
	in := testfixture.MieruIntent(t, "tcp")
	in.Inbound.Protocol = module.Key()
	in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{Mode: "https", TLS: testkit.TLS(t)})
	m := module.Module{}
	if _, err := m.BuildRuntime(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	p, err := m.BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: in.Inbound, Binding: in.Bindings[0], Credential: in.Credentials[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !p.TLS.Enabled || p.UDPPayload || p.Transport.Kind != "tcp" || !reflect.DeepEqual(p.TLS.ALPN, []string{"h2"}) {
		t.Fatal("profile capability")
	}
	password := in.Credentials[0].Payload.(access.UsernamePasswordPayload).Password.Reveal()
	if strings.Contains(fmt.Sprintf("%+v", p), password) {
		t.Fatal("profile secret exposed")
	}
	original := in.Credentials[1]
	in.Credentials[1].Payload = in.Credentials[0].Payload
	if _, err := m.BuildRuntime(context.Background(), in); err == nil {
		t.Fatal("duplicate username")
	}
	in.Credentials[1] = original
	in.Credentials[1].OwnerAccountID = &in.Bindings[0].AccountID
	if _, err := m.BuildRuntime(context.Background(), in); err == nil {
		t.Fatal("account crossover")
	}
	in.Credentials[1] = original
	in.Bindings[1].Enabled = false
	if _, err := m.BuildRuntime(context.Background(), in); err == nil {
		t.Fatal("disabled binding")
	}
}
func TestNaiveConfigurationValidation(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `{"mode":"https","mode":"quic"}`, `{"Mode":"https"}`, `{"mode":"https","padding":null}`, `{"mode":"https","padding":"maybe"}`, `{"mode":"https","max_connections":-1}`, `{"mode":"https","max_connections":5}`, `{"mode":"quic","max_streams":513}`, `{"mode":"https","connect_timeout":"0s"}`, `{"mode":"https","idle_timeout":"25h"}`, `{"mode":"quic","congestion_control":"bbr"}`, `{"mode":"https","congestion_control":"cubic"}`, `{"mode":"https","udp":true}`, `{"mode":"https","extra_headers":{"pAdDiNg":"x"}}`, `{"mode":"https","extra_headers":{"X-Test":"a\r\nb"}}`} {
		if _, err := module.DecodeClient([]byte(raw)); err == nil {
			t.Fatal("accepted", raw)
		}
	}
	for _, mode := range []string{"https", "quic"} {
		o, err := module.DecodeClient([]byte(`{"mode":"` + mode + `"}`))
		if err != nil || o.MaxConnections != 1 || o.MaxStreams != 128 || o.Padding != "auto" {
			t.Fatal("defaults", err)
		}
	}
	settings := module.Settings{Mode: "https", TLS: testkit.TLS(t)}
	good, _ := json.Marshal(settings)
	if _, err := module.Decode(good); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{}`, `{"tls":null,"mode":"https"}`, `{"mode":"http","tls":{}}`, `{"mode":"https","tls":{},"unknown":1}`} {
		if _, err := module.Decode([]byte(raw)); err == nil {
			t.Fatal("settings accepted", raw)
		}
	}
}
func TestNaiveCreationGenerationFlagsAndPolicy(t *testing.T) {
	settings := module.Settings{Mode: "https", TLS: testkit.TLS(t)}
	doc := map[string]any{"schema": 1, "name": "Naive test", "listener": access.Endpoint{Host: "127.0.0.1", Port: 443}, "display_endpoint": access.Endpoint{Host: "localhost", Port: 443}, "settings": settings}
	doc["users"] = []any{map[string]any{"account_name": "Alpha", "username": "alpha", "account_enabled": false}, map[string]any{"account_name": "Beta", "username": "beta", "password": "beta-secret", "enabled": false}}
	b, _ := json.Marshal(doc)
	draft, err := (module.Module{}).DecodeCreation(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(draft.Users) != 2 || draft.Users[0].AccountEnabled || draft.Users[1].Enabled {
		t.Fatal("creation flags")
	}
	generated, err := (module.Module{}).GenerateCreationCredential(draft.Users[0].Payload)
	if err != nil || generated.(access.UsernamePasswordPayload).Password.Empty() {
		t.Fatal("password generation", err)
	}
	for _, u := range []map[string]any{{"account_name": "X", "username": "bad:name"}, {"account_name": "X", "username": "bad\nname"}, {"account_name": "X", "username": nil}, {"account_name": "X", "username": "ok", "password": nil}, {"account_name": "X", "username": "ok", "enabled": nil}} {
		doc["users"] = []any{u}
		b, _ := json.Marshal(doc)
		if _, err := (module.Module{}).DecodeCreation(b); err == nil {
			t.Fatal("invalid user accepted")
		}
	}
	doc["users"] = []any{map[string]any{"account_name": "X", "username": "ok", "traffic_policy": map[string]any{"quota_bytes": 1}}}
	b, _ = json.Marshal(doc)
	_, err = (module.Module{}).DecodeCreation(b)
	var policy *creation.UnsupportedStrictPolicy
	if !errors.As(err, &policy) {
		t.Fatal("strict policy type lost", err)
	}
}
func TestNaiveURIRoundTripAndStrictSubset(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		for _, host := range []string{"::1", "localhost", "192.0.2.1"} {
			v := module.URI{Mode: mode, Name: "测试 node", Endpoint: access.Endpoint{Host: host, Port: 443}, Credentials: access.UsernamePasswordPayload{Username: secret.New("user@x"), Password: secret.New("p:@+/secret")}}
			u, err := module.EncodeURI(v)
			if err != nil {
				t.Fatal(err)
			}
			got, err := module.ParseURI(u)
			if err != nil || got.Mode != v.Mode || got.Name != v.Name || got.Endpoint != v.Endpoint || got.Credentials.Username.Reveal() != v.Credentials.Username.Reveal() || got.Credentials.Password.Reveal() != v.Credentials.Password.Reveal() {
				t.Fatal("URI semantic loss", err)
			}
		}
	}
	v, err := module.ParseURI("naive+https://u:p@localhost")
	if err != nil || v.Endpoint.Port != 443 {
		t.Fatal(err)
	}
	for _, raw := range []string{"naive+https://u@localhost", "naive+https://u:p@localhost:", "naive+https://u:p@localhost:0", "naive+quic://u:p@localhost:65536", "naive+https://u:p@localhost/?x=1", "naive+https://u:p@localhost?", "naive+https://u:p@localhost/path", "naive+https://bad%3Auser:p@localhost", "naive+https://u:bad%0Apass@localhost", "naive+http://u:p@localhost"} {
		if _, err := module.ParseURI(raw); err == nil {
			t.Fatal(raw)
		}
	}
}
