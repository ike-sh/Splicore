package exporter

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/credential"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	hm "github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"github.com/sagernet/sing-box/internal/splicore/tlsconfig"
	"strings"
	"testing"
)

func TestTUICPinnedExportContractsAndTLSVerification(t *testing.T) {
	id, _ := identity.NewID()
	tls := testkit.TLSForName(t, "tuic.synthetic.test")
	for _, host := range []string{"127.0.0.1", "::1", "public.synthetic.test"} {
		for _, format := range []ports.Format{ports.Mihomo, ports.SingBox} {
			p := clientprofile.Profile{ID: id, Schema: 1, Protocol: hm.Key(), Endpoint: access.Endpoint{Host: host, Port: 4433}, Credentials: access.UUIDPasswordPayload{UUID: secret.New("68f4f564-142b-46b3-8c89-322a37ef1b30"), Password: secret.New("SyntheticExportPassword")}, TLS: clientprofile.TLS{Enabled: true, ServerName: tls.ServerName, ALPN: []string{"h3"}, Trust: "explicit_ca", CACertificate: tls.CACertificate}, Transport: clientprofile.Transport{Kind: "quic"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: []byte(`{"version":5,"congestion_control":"cubic","udp_relay_mode":"native","zero_rtt_handshake":false}`)}}
			version := "1.14.1"
			if format == ports.Mihomo {
				version = "1.19.30"
			}
			x := TUIC{Target: format}
			b, e := x.Export(context.Background(), p, ports.ExportTarget{Format: format, ClientVersion: version})
			if e != nil {
				t.Fatal(e)
			}
			var out map[string]any
			if json.Unmarshal(b, &out) != nil {
				t.Fatal("invalid JSON")
			}
			node := out
			if format == ports.Mihomo {
				node = out["proxies"].([]any)[0].(map[string]any)
				pin, _ := tlsconfig.CAFingerprint(tls.CACertificate)
				if node["fingerprint"] != pin || node["skip-cert-verify"] != false || node["sni"] != tls.ServerName {
					t.Fatal("CA anchor/SNI lost")
				}
			} else {
				security := out["tls"].(map[string]any)
				if security["insecure"] != false || security["server_name"] != tls.ServerName || security["certificate"].([]any)[0] != tls.CACertificate {
					t.Fatal("CA trust/SNI lost")
				}
			}
			if node["uuid"] != "68f4f564-142b-46b3-8c89-322a37ef1b30" || node["token"] != nil {
				t.Fatal("UUID/v5 token projection")
			}
			if node["server"] != host || node["password"] != "SyntheticExportPassword" || strings.Contains(string(b), tls.PrivateKeyFile) {
				t.Fatal("endpoint/credential projection")
			}
			if _, e = x.Export(context.Background(), p, ports.ExportTarget{Format: format, ClientVersion: "latest"}); e == nil {
				t.Fatal("unpinned export")
			}
			for _, mutate := range []func(*clientprofile.Profile){func(p *clientprofile.Profile) {
				p.Options.Data = []byte(`{"version":5,"congestion_control":"cubic","udp_relay_mode":"native","zero_rtt_handshake":null}`)
			}, func(p *clientprofile.Profile) { p.TLS.Trust = "insecure" }, func(p *clientprofile.Profile) { p.UDPPayload = false }, func(p *clientprofile.Profile) { p.Transport.Path = "/unsupported" }, func(p *clientprofile.Profile) { p.Options.Data = []byte(`{"obfs":"unqualified"}`) }, func(p *clientprofile.Profile) {
				p.Credentials = access.PSKPayload{Key: secret.New("SyntheticExportPassword")}
			}} {
				bad := p
				mutate(&bad)
				if _, e = x.Export(context.Background(), bad, ports.ExportTarget{Format: format, ClientVersion: version}); e == nil {
					t.Fatal("silent omission/unsafe export")
				}
			}
		}
	}
}

func FuzzTUICExport(f *testing.F) {
	f.Add("127.0.0.1", "SyntheticExportPassword", "hy2.synthetic.test", "1.14.1")
	f.Add("::1", "SyntheticExportPassword", "hy2.synthetic.test", "1.19.30")
	f.Add("host, injection", "password\nsecret", "wrong\nname", "latest")
	tls := testkit.TLSForName(f, "tuic.synthetic.test")
	id, err := identity.NewID()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, host, password, sni, version string) {
		p := clientprofile.Profile{ID: id, Schema: 1, Protocol: hm.Key(), Endpoint: access.Endpoint{Host: host, Port: 4433}, Credentials: access.UUIDPasswordPayload{UUID: secret.New("68f4f564-142b-46b3-8c89-322a37ef1b30"), Password: secret.New(password)}, TLS: clientprofile.TLS{Enabled: true, ServerName: sni, ALPN: []string{"h3"}, Trust: "explicit_ca", CACertificate: tls.CACertificate}, Transport: clientprofile.Transport{Kind: "quic"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: []byte(`{"version":5,"congestion_control":"cubic","udp_relay_mode":"native","zero_rtt_handshake":false}`)}}
		for _, format := range []ports.Format{ports.Mihomo, ports.SingBox} {
			target := ports.ExportTarget{Format: format, ClientVersion: version}
			b, err := (TUIC{Target: format}).Export(context.Background(), p, target)
			if err != nil {
				if len(b) != 0 {
					t.Fatal("rejected export returned content")
				}
				continue
			}
			if !json.Valid(b) || strings.ContainsAny(string(b), "\r\n") || strings.Contains(string(b), "PRIVATE KEY") {
				t.Fatal("invalid or unsafe export")
			}
			var node map[string]any
			if err := json.Unmarshal(b, &node); err != nil {
				t.Fatal(err)
			}
			if format == ports.Mihomo {
				node = node["proxies"].([]any)[0].(map[string]any)
				pin, _ := tlsconfig.CAFingerprint(tls.CACertificate)
				if version != "1.19.30" || node["sni"] != sni || node["skip-cert-verify"] != false || node["fingerprint"] != pin {
					t.Fatal("Mihomo trust/version changed")
				}
			} else {
				security := node["tls"].(map[string]any)
				if version != "1.14.1" || security["server_name"] != sni || security["insecure"] != false || security["certificate"].([]any)[0] != tls.CACertificate {
					t.Fatal("sing-box trust/version changed")
				}
			}
			if node["uuid"] != "68f4f564-142b-46b3-8c89-322a37ef1b30" || node["token"] != nil {
				t.Fatal("UUID/v5 token projection")
			}
			if node["server"] != host || node["password"] != password || credential.ValidatePassword(secret.New(password)) != nil {
				t.Fatal("credential/endpoint projection changed")
			}
		}
	})
}
