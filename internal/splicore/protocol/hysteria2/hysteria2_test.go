package hysteria2_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	hm "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"strings"
	"testing"
	"time"
)

func intent(t *testing.T) ports.RuntimeIntent {
	t.Helper()
	id := func() identity.ID {
		v, e := identity.NewID()
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	stamp := identity.NewStamp(time.Now())
	data, _ := json.Marshal(hm.Settings{TLS: testkit.TLS(t)})
	i := access.Inbound{ID: id(), NodeID: id(), Name: "synthetic", Protocol: hm.Key(), Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: id(), Transport: "udp", Endpoint: access.Endpoint{Host: "0.0.0.0", Port: 4433}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: id(), Endpoint: access.Endpoint{Host: "public.synthetic.test", Port: 7443}}}, Settings: access.Settings{Schema: 1, Data: data}, Stamp: stamp}
	in := ports.RuntimeIntent{Inbound: i}
	for _, password := range []string{"SyntheticAlicePassword", "SyntheticBobPassword"} {
		aid, cid := id(), id()
		in.Bindings = append(in.Bindings, access.Binding{ID: id(), AccountID: aid, InboundID: i.ID, CredentialID: cid, Enabled: true, Stamp: stamp})
		in.Credentials = append(in.Credentials, access.Credential{ID: cid, OwnerAccountID: &aid, Kind: access.Password, Schema: 1, State: "active", Payload: access.PasswordPayload{Password: secret.New(password)}, Stamp: stamp})
	}
	return in
}
func TestHysteria2CapabilitiesProjectionOwnership(t *testing.T) {
	m := hm.Module{}
	in := intent(t)
	if _, e := m.BuildRuntime(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	cap := m.Capabilities(ports.CapabilityContext{})
	if !cap.Identity.MultiUserNative || !cap.Transport.UDPTransport || !cap.Transport.UDPPayload || !cap.Security.TLS || cap.Mutation.Users != ports.Restart || cap.Policy.SpeedLimit != ports.Unsupported {
		t.Fatal("capabilities untrue")
	}
	p, e := m.BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: in.Inbound, Binding: in.Bindings[0], Credential: in.Credentials[0]})
	if e != nil {
		t.Fatal(e)
	}
	if p.Endpoint.Host != "public.synthetic.test" || p.Endpoint.Port != 7443 || p.TLS.ServerName != "hy2.synthetic.test" || p.Transport.Kind != "quic" || !p.UDPPayload || p.TLS.Trust != "explicit_ca" {
		t.Fatal("endpoint/SNI/transport conflated")
	}
	encoded, _ := json.Marshal(p)
	if strings.Contains(string(encoded), "SyntheticAlicePassword") || strings.Contains(fmt.Sprintf("%+v", p), "SyntheticAlicePassword") {
		t.Fatal("profile secret exposed")
	}
	in.Credentials[1].OwnerAccountID = &in.Bindings[0].AccountID
	if _, e = m.BuildRuntime(context.Background(), in); e == nil {
		t.Fatal("cross-owner credential accepted")
	}
	in = intent(t)
	in.Credentials[1].Payload = in.Credentials[0].Payload
	if _, e = m.BuildRuntime(context.Background(), in); e == nil {
		t.Fatal("duplicate password identity accepted")
	}
	in = intent(t)
	in.Bindings[0].Enabled = false
	if _, e = m.BuildRuntime(context.Background(), in); e == nil {
		t.Fatal("disabled binding admitted")
	}
	in = intent(t)
	in.Bindings = nil
	in.Credentials = nil
	if _, e = m.BuildRuntime(context.Background(), in); e != nil {
		t.Fatal("empty user deny-all runtime unavailable", e)
	}
}
func TestPasswordAndStrictTLSValidation(t *testing.T) {
	for _, p := range []string{"", strings.Repeat("x", 11), strings.Repeat("x", 256), "abcdefghijkl\x00", "abcdefghijkl\u2000", string([]byte{255})} {
		if hm.ValidatePassword(secret.New(p)) == nil {
			t.Fatal("invalid password accepted")
		}
	}
	seen := map[string]bool{}
	for range 64 {
		p, e := hm.GeneratePassword()
		if e != nil || hm.ValidatePassword(p) != nil || len(p.Reveal()) != 43 || seen[p.Reveal()] {
			t.Fatal("password generation")
		}
		seen[p.Reveal()] = true
	}
	tls := testkit.TLS(t)
	b, _ := json.Marshal(hm.Settings{TLS: tls})
	for _, data := range []string{strings.Replace(string(b), `"tls":`, `"obfs":"x","tls":`, 1), strings.Replace(string(b), "hy2.synthetic.test", "127.0.0.1", 1), `{"tls":null}`} {
		if _, e := hm.Decode([]byte(data)); e == nil {
			t.Fatal("invalid TLS/settings accepted")
		}
	}
	if _, e := hm.CAPool("junk" + tls.CACertificate); e == nil {
		t.Fatal("noncertificate PEM accepted")
	}
}
func FuzzHysteria2Settings(f *testing.F) {
	f.Add([]byte(`{"tls":null}`))
	f.Add([]byte(`{"tls":{"server_name":"hy2.synthetic.test"}}`))
	f.Add([]byte(`{"obfs":"unsupported"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, e := hm.Decode(b)
		if e == nil {
			encoded, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = hm.Decode(encoded); err != nil {
				t.Fatal("accepted settings not roundtrip stable")
			}
		}
	})
}
