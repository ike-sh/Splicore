package trusttunnel_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trusttunnel"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/deeplink"
	"strings"
	"testing"
)

func TestOwnedIntentCreationAndProfile(t *testing.T) {
	in := testfixture.MieruIntentAt(t, "tcp", access.Endpoint{Host: "127.0.0.1", Port: 443})
	in.Inbound.Protocol = module.Key()
	settings := module.Settings{Mode: "http2", TLS: testkit.TLS(t)}
	in.Inbound.Settings.Data, _ = json.Marshal(settings)
	m := module.Module{}
	if _, e := m.BuildRuntime(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	p, e := m.BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: in.Inbound, Binding: in.Bindings[0], Credential: in.Credentials[0]})
	if e != nil || !p.UDPPayload || !p.TLS.Enabled {
		t.Fatal(e)
	}
	uri, e := module.ExportLink(p)
	if e != nil {
		t.Fatal(e)
	}
	node, u, password, e := module.ImportLink(uri)
	if e != nil || node.Endpoint != p.Endpoint || u == "" || password == "" || node.Security.TLS.CACertificate != p.TLS.CACertificate {
		t.Fatal("profile/URI loss", e)
	}
	if strings.Contains(fmt.Sprint(p), password) {
		t.Fatal("secret diagnostic")
	}
	original := in.Credentials[1]
	in.Credentials[1].Payload = in.Credentials[0].Payload
	if _, e := m.BuildRuntime(context.Background(), in); e == nil {
		t.Fatal("duplicate user")
	}
	in.Credentials[1] = original
	in.Credentials[1].OwnerAccountID = &in.Bindings[0].AccountID
	if _, e := m.BuildRuntime(context.Background(), in); e == nil {
		t.Fatal("credential crossover")
	}
	settings.Mode = "auto"
	doc := map[string]any{"schema": 1, "name": "test TrustTunnel", "listener": access.Endpoint{Host: "127.0.0.1", Port: 443}, "display_endpoint": access.Endpoint{Host: "vpn.test", Port: 443}, "settings": settings, "users": []any{map[string]any{"account_name": "A", "username": "test"}}}
	raw, _ := json.Marshal(doc)
	draft, e := m.DecodeCreation(raw)
	if e != nil || len(draft.AdditionalTransports) != 1 || draft.AdditionalTransports[0] != "udp" {
		t.Fatal("dual creation", e)
	}
}
func TestStrictConfigurationAndExplicitBoundaries(t *testing.T) {
	for _, s := range []string{`{}`, `null`, `{"mode":"HTTP2"}`, `{"mode":"http2","mode":"http3"}`, `{"Mode":"http2"}`, `{"mode":"http2","max_streams":null}`, `{"mode":"http2","extra_headers":{"proxy-authorization":"x"}}`, `{"mode":"http3","max_streams":999}`, `{"mode":"auto","fallback_delay":"0s"}`, `{"mode":"http2","custom_sni":"127.0.0.1"}`, `{"mode":"http2","addresses":["http://a"]}`, `{"mode":"http2","user_agent":"a\r\nb"}`, `{"mode":"http2","health_check_timeout":"25h"}`} {
		if _, e := module.DecodeClient([]byte(s)); e == nil {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"http2", "http3", "auto"} {
		o, e := module.DecodeClient([]byte(`{"mode":"` + s + `"}`))
		if e != nil || o.MaxStreams != 256 || o.MaxFlows != 256 {
			t.Fatal(e)
		}
	}
	l := deeplink.Link{Hostname: "vpn.test", Addresses: []string{"192.0.2.1:443"}, HasIPv6: true, Protocol: "http2", Username: "u", Password: "p"}
	for _, extension := range []string{"dns", "anti", "random", "subscription"} {
		v := l
		switch extension {
		case "dns":
			v.DNSUpstreams = []string{"1.1.1.1"}
		case "anti":
			v.AntiDPI = true
		case "random":
			v.ClientRandomAuthKey = "aabb"
		case "subscription":
			v.SubscriptionURL = "https://example.test/config"
		}
		u, e := deeplink.Encode(v)
		if e != nil {
			t.Fatal(e)
		}
		if _, _, _, e := module.ImportLink(u); e == nil {
			t.Fatal("silently stripped", extension)
		}
	}
}
func FuzzConfiguration(f *testing.F) {
	f.Add([]byte(`{"mode":"http2"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 16385 {
			return
		}
		_, _ = module.DecodeClient(b)
		_, _ = module.Decode(b)
	})
}
