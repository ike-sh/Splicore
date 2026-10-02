package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/mieru"
	"strings"
	"testing"
)

func mieruProfile(t *testing.T, host string) clientprofile.Profile {
	t.Helper()
	id, e := identity.NewID()
	if e != nil {
		t.Fatal(e)
	}
	return clientprofile.Profile{ID: id, Schema: 1, Protocol: module.Key(), Endpoint: access.Endpoint{Host: host, Port: 12345}, Credentials: access.UsernamePasswordPayload{Username: secret.New("synthetic-Alice"), Password: secret.New("SyntheticPasswordForPhase8")}, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: []byte(`{"transport":"tcp","mtu":1500,"multiplex":"default"}`)}, Metadata: identity.Metadata{}}
}

func TestMieruFormatsEndpointAndRedaction(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		p := mieruProfile(t, host)
		p.Protocol = module.Key()
		p.TLS.Enabled = false
		p.TLS.ServerName = ""
		p.TLS.RealityPublicKey = ""
		p.TLS.RealityShortID = ""
		p.TLS.Trust = ""
		p.TLS.CACertificate = ""
		p.TLS.ALPN = nil
		p.Credentials = access.UsernamePasswordPayload{Username: secret.New("synthetic-Alice"), Password: secret.New("SyntheticPasswordForPhase8")}
		p.Transport.Kind = "tcp"
		p.UDPPayload = true
		p.Options.Data = []byte(`{"transport":"tcp","mtu":1500,"multiplex":"default"}`)
		for _, format := range []ports.Format{ports.Mieru, ports.Mihomo} {
			version := module.ReferenceVersion
			if format == ports.Mihomo {
				version = "1.19.30"
			}
			data, e := (Mieru{Target: format}).Export(context.Background(), p, ports.ExportTarget{Format: format, ClientVersion: version})
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(string(data), host) || !strings.Contains(string(data), "SyntheticPasswordForPhase8") || strings.Contains(string(data), "private_key") || strings.Contains(string(data), "engine") {
				t.Fatal("wrong endpoint or client projection")
			}
			if _, e = (Mieru{Target: format}).Export(context.Background(), p, ports.ExportTarget{Format: format, ClientVersion: "unknown"}); e == nil {
				t.Fatal("unqualified version accepted")
			}
		}
		for _, format := range []ports.Format{ports.SingBox, ports.Surge, ports.URI, ports.Xray} {
			if _, e := (Mieru{Target: format}).Export(context.Background(), p, ports.ExportTarget{Format: format, ClientVersion: "1.14.1"}); e == nil {
				t.Fatal("unsupported client accepted")
			}
		}
		data, _ := json.Marshal(p)
		if strings.Contains(string(data), "SyntheticPasswordForPhase8") || strings.Contains(fmt.Sprintf("%+v %#v", p, p), "SyntheticPasswordForPhase8") {
			t.Fatal("implicit credential leak")
		}
	}
}
func FuzzMieruProfileExporter(f *testing.F) {
	f.Add([]byte(`{"transport":"tcp","mtu":1500,"multiplex":"default"}`), "localhost")
	f.Add([]byte(`null`), "127.0.0.1")
	f.Fuzz(func(t *testing.T, options []byte, host string) {
		p := mieruProfile(t, host)
		p.Protocol = module.Key()
		p.TLS.Enabled = false
		p.TLS.ServerName = ""
		p.TLS.RealityPublicKey = ""
		p.TLS.RealityShortID = ""
		p.Transport.Kind = "tcp"
		p.Credentials = access.UsernamePasswordPayload{Username: secret.New("synthetic-Alice"), Password: secret.New("SyntheticPasswordForPhase8")}
		p.UDPPayload = true
		p.Options = access.Settings{Schema: 1, Data: options}
		data, e := (Mieru{Target: ports.Mieru}).Export(context.Background(), p, ports.ExportTarget{Format: ports.Mieru, ClientVersion: module.ReferenceVersion})
		if e == nil && !json.Valid(data) {
			t.Fatal("invalid exported JSON")
		}
	})
}

func TestMieruRejectsUnrepresentedSecurityOptions(t *testing.T) {
	for _, tls := range []clientprofile.TLS{{Enabled: true}, {ServerName: "synthetic.test"}, {ALPN: []string{"h2"}}, {Trust: "insecure"}, {CACertificate: "unexpected"}, {RealityPublicKey: "unexpected"}, {RealityShortID: "0123"}} {
		p := mieruProfile(t, "localhost")
		p.TLS = tls
		if _, err := (Mieru{Target: ports.Mieru}).Export(context.Background(), p, ports.ExportTarget{Format: ports.Mieru, ClientVersion: module.ReferenceVersion}); err == nil {
			t.Fatal("security option silently dropped")
		}
	}
}
