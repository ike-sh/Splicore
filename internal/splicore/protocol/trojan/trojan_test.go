package trojan_test

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
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func TestManagedTrojanOwnershipTLSAndCredentials(t *testing.T) {
	in := testfixture.MieruIntent(t, "tcp")
	in.Inbound.Protocol = module.Key()
	in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{TLS: testkit.TLS(t)})
	for i := range in.Credentials {
		pass := in.Credentials[i].Payload.(access.UsernamePasswordPayload).Password
		in.Credentials[i].Kind = access.Password
		in.Credentials[i].Payload = access.PasswordPayload{Password: pass}
	}
	m := module.Module{}
	if _, err := m.BuildRuntime(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	p, err := m.BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: in.Inbound, Binding: in.Bindings[0], Credential: in.Credentials[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !p.TLS.Enabled || p.TLS.Trust != "explicit_ca" || p.Transport.Kind != "tcp" || !p.UDPPayload || len(p.TLS.ALPN) != 0 {
		t.Fatal("nonstandard TLS profile")
	}
	password := in.Credentials[0].Payload.(access.PasswordPayload).Password.Reveal()
	encoded, _ := json.Marshal(p)
	if strings.Contains(string(encoded), password) || strings.Contains(fmt.Sprintf("%+v", p), password) {
		t.Fatal("client profile leaked password")
	}
	original := in.Credentials[1]
	in.Credentials[1].Payload = in.Credentials[0].Payload
	if _, err = m.BuildRuntime(context.Background(), in); err == nil {
		t.Fatal("duplicate wire identity accepted")
	}
	in.Credentials[1] = original
	in.Credentials[1].OwnerAccountID = &in.Bindings[0].AccountID
	if _, err = m.BuildRuntime(context.Background(), in); err == nil {
		t.Fatal("cross-account credential accepted")
	}
	for _, bad := range []string{`{}`, `{"tls":false}`, `{"tls":null}`, `{"security":"none"}`, `{"transport":"ws"}`} {
		if _, err := module.Decode([]byte(bad)); err == nil {
			t.Fatal("TLS/config bypass accepted")
		}
	}
	for _, bad := range []string{`{"udp":null}`, `{"udp":"true"}`, `{"udp":true,"udp":false}`, `{"mux":true}`} {
		if _, err := module.DecodeClientOptions([]byte(bad)); err == nil {
			t.Fatal("ambiguous client options accepted")
		}
	}
}
func TestTrojanURIRoundTripSecurity(t *testing.T) {
	v := module.URI{Endpoint: access.Endpoint{Host: "::1", Port: 443}, Password: secret.New("Synthetic:@+/Password"), TLS: access.ClientTLS{Enabled: true, ServerName: "trojan.synthetic.test", ALPN: []string{"http/1.1"}, Trust: "system"}, Name: "Synthetic node"}
	u, err := module.EncodeURI(v)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := module.ParseURI(u)
	if err != nil || parsed.Endpoint != v.Endpoint || parsed.Password.Reveal() != v.Password.Reveal() || !reflect.DeepEqual(parsed.TLS, v.TLS) || parsed.Name != v.Name {
		t.Fatal("URI semantic loss")
	}
	for _, suffix := range []string{"?type=ws", "?security=none", "?insecure=1", "?allowInsecure=1", "?mux=1", "?sni=x&sni=y", "?sni=a&peer=b", "?alpn=", "?sni=bad%0Aname"} {
		if _, err := module.ParseURI("trojan://SyntheticPassword@127.0.0.1:443" + suffix); err == nil {
			t.Fatal("unsupported URI accepted", suffix)
		}
	}
	for _, uri := range []string{"trojan://@localhost:443", "trojan://SyntheticPassword@localhost:0", "trojan://SyntheticPassword@localhost:65536", "trojan://SyntheticPassword@localhost:443#bad%0Aname", "trojan://Synthetic%00Password@localhost:443", "trojan://Synthetic@Password@localhost:443", "trojan://Synthetic%ZZPassword@localhost:443"} {
		if _, err := module.ParseURI(uri); err == nil {
			t.Fatal("malformed URI accepted")
		}
	}
	v.TLS.Trust = "explicit_ca"
	v.TLS.CACertificate = testkit.TLS(t).CACertificate
	if _, err := module.EncodeURI(v); err == nil {
		t.Fatal("CA trust silently dropped")
	}
}
func FuzzTrojanURI(f *testing.F) {
	f.Add("trojan://SyntheticPassword@127.0.0.1:443?sni=trojan.synthetic.test#fixture")
	f.Add("trojan://")
	f.Fuzz(func(t *testing.T, s string) {
		v, err := module.ParseURI(s)
		if err == nil {
			u, e := module.EncodeURI(v)
			if e != nil {
				t.Fatal(e)
			}
			copy, e := module.ParseURI(u)
			if e != nil || copy.Endpoint != v.Endpoint || copy.Password.Reveal() != v.Password.Reveal() || !reflect.DeepEqual(copy.TLS, v.TLS) || copy.Name != v.Name {
				t.Fatal("URI round trip lost configuration")
			}
		}
	})
}
