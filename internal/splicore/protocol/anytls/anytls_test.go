package anytls_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/anytls"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func TestManagedAnyTLSOwnershipTLSAndValidation(t *testing.T) {
	in := testfixture.MieruIntent(t, "tcp")
	in.Inbound.Protocol = module.Key()
	in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{TLS: testkit.TLS(t)})
	for i := range in.Credentials {
		p := in.Credentials[i].Payload.(access.UsernamePasswordPayload).Password
		in.Credentials[i].Kind = access.Password
		in.Credentials[i].Payload = access.PasswordPayload{Password: p}
	}
	m := module.Module{}
	if _, err := m.BuildRuntime(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	p, err := m.BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: in.Inbound, Binding: in.Bindings[0], Credential: in.Credentials[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !p.TLS.Enabled || p.TLS.Trust != "explicit_ca" || !p.UDPPayload {
		t.Fatal("security profile")
	}
	password := in.Credentials[0].Payload.(access.PasswordPayload).Password.Reveal()
	if strings.Contains(fmt.Sprintf("%+v", p), password) {
		t.Fatal("profile secret leak")
	}
	original := in.Credentials[1]
	in.Credentials[1].Payload = in.Credentials[0].Payload
	if _, err = m.BuildRuntime(context.Background(), in); err == nil {
		t.Fatal("duplicate auth")
	}
	in.Credentials[1] = original
	in.Credentials[1].OwnerAccountID = &in.Bindings[0].AccountID
	if _, err = m.BuildRuntime(context.Background(), in); err == nil {
		t.Fatal("cross account")
	}
	in.Credentials[1] = original
	in.Bindings[1].Enabled = false
	if _, err = m.BuildRuntime(context.Background(), in); err == nil {
		t.Fatal("disabled binding entered snapshot")
	}
	for _, bad := range []string{`{}`, `{"tls":false}`, `{"tls":null}`, `{"security":"none"}`, `{"tls":{},"version":3}`} {
		if _, err := module.Decode([]byte(bad)); err == nil {
			t.Fatal(bad)
		}
	}
	for _, bad := range []string{`{"udp":null}`, `{"udp":"true"}`, `{"udp":true,"udp":false}`, `{"idle_session_timeout":"-1s"}`, `{"idle_session_check_interval":"0s"}`, `{"min_idle_session":-1}`, `{"version":3}`, `{"uot_mode":"v1"}`, `{"client_metadata":"sing-box"}`, `{"max_sessions":129}`, `{"multiplex_streams":129}`} {
		if _, err := module.DecodeClientOptions([]byte(bad)); err == nil {
			t.Fatal(bad)
		}
	}
	o, err := module.DecodeClientOptions([]byte(`{}`))
	if err != nil || o.Insecure || o.ClientMetadata != "" || o.Version != 2 {
		t.Fatal("unsafe defaults", err)
	}
}
func TestAnyTLSURIRoundTripAndSecurity(t *testing.T) {
	for _, host := range []string{"::1", "example.test", "192.0.2.1"} {
		for _, insecure := range []bool{false, true} {
			v := module.URI{Endpoint: access.Endpoint{Host: host, Port: 443}, Password: secret.New("Synthetic:@+/Password"), TLS: access.ClientTLS{Enabled: true, ServerName: "anytls.synthetic.test", Trust: "system"}, Name: "测试 node", Insecure: insecure}
			u, err := module.EncodeURI(v)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := module.ParseURI(u)
			if err != nil || parsed.Endpoint != v.Endpoint || parsed.Password.Reveal() != v.Password.Reveal() || !reflect.DeepEqual(parsed.TLS, v.TLS) || parsed.Name != v.Name || parsed.Insecure != insecure {
				t.Fatal("URI semantic loss", err)
			}
		}
	}
	v, err := module.ParseURI("anytls://SyntheticPassword@example.test")
	if err != nil || v.Endpoint.Port != 443 || v.Insecure {
		t.Fatal("default", err)
	}
	for _, suffix := range []string{"?insecure=true", "?insecure=2", "?sni=x&sni=y", "?alpn=h2", "?sni=bad%0Aname", "?sni=x&insecure=0&insecure=1"} {
		if _, err := module.ParseURI("anytls://SyntheticPassword@127.0.0.1:443" + suffix); err == nil {
			t.Fatal(suffix)
		}
	}
	for _, bad := range []string{"anytls://@localhost", "anytls://SyntheticPassword@localhost:0", "anytls://SyntheticPassword@localhost:65536", "anytls://Synthetic%00Password@localhost", "anytls://Synthetic@Password@localhost", "anytls://Synthetic:Password@localhost", "anytls://Synthetic%ZZPassword@localhost"} {
		if _, err := module.ParseURI(bad); err == nil {
			t.Fatal(bad)
		}
	}
	v.TLS.Trust = "explicit_ca"
	v.TLS.CACertificate = testkit.TLS(t).CACertificate
	if _, err := module.EncodeURI(v); err == nil {
		t.Fatal("CA dropped")
	}
}
