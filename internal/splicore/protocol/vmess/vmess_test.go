package vmess_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"reflect"
	"strings"
	"testing"
)

const syntheticUUID = "00000000-0000-1000-8000-000000000001"

func link(b string) string { return "vmess://" + base64.StdEncoding.EncodeToString([]byte(b)) }
func TestManagedVMessCredentialsAndScope(t *testing.T) {
	in := testfixture.MieruIntent(t, "tcp")
	in.Inbound.Protocol = module.Key()
	in.Inbound.Settings.Data = json.RawMessage(`{"transport":"tcp","security":"none","payload_security":"auto","alter_id":0}`)
	for i := range in.Credentials {
		in.Credentials[i].Kind = access.UUID
		in.Credentials[i].Payload = access.UUIDPayload{UUID: secret.New(fmt.Sprintf("00000000-0000-%d000-8000-000000000001", i+1))}
	}
	m := module.Module{}
	if _, err := m.BuildRuntime(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	p, err := m.BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: in.Inbound, Binding: in.Bindings[0], Credential: in.Credentials[0]})
	if err != nil || p.TLS.Enabled || !p.UDPPayload {
		t.Fatal("managed profile", err)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), syntheticUUID) || strings.Contains(fmt.Sprintf("%+v", p), syntheticUUID) {
		t.Fatal("profile secret leak")
	}
	in.Credentials[1].Payload = in.Credentials[0].Payload
	if _, err = m.BuildRuntime(context.Background(), in); err == nil {
		t.Fatal("duplicate identity accepted")
	}
	for _, bad := range []string{`{"alter_id":64}`, `{"transport":"ws"}`, `{"payload_security":"aes-128-cfb"}`, `{"payload_security":"zero"}`, `{"alter_id":null}`, `{"payload_security":"auto","payload_security":"none"}`, `{"authenticated_length":true}`, `{"security":"reality"}`} {
		if _, err := module.Decode([]byte(bad)); err == nil {
			t.Fatal("unsupported settings accepted")
		}
	}
	for _, bad := range []string{`{"udp":null}`, `{"alter_id":64}`, `{"security":"zero"}`, `{"udp":true,"udp":false}`, `{"mux":true}`} {
		if _, err := module.DecodeClientOptions([]byte(bad)); err == nil {
			t.Fatal("unsupported options accepted")
		}
	}
}
func TestVMessURIAndPeerSemanticRoundTrips(t *testing.T) {
	for _, security := range []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none"} {
		for _, tls := range []bool{false, true} {
			v := module.URI{Endpoint: access.Endpoint{Host: "::1", Port: 443}, UUID: secret.New(syntheticUUID), Security: security, Name: "Synthetic VMess"}
			if tls {
				v.TLS = access.ClientTLS{Enabled: true, ServerName: "vmess.synthetic.test", Trust: "system", ALPN: []string{"http/1.1"}}
			}
			u, err := module.EncodeURI(v)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := module.ParseURI(u)
			if err != nil || parsed.Endpoint != v.Endpoint || parsed.UUID.Reveal() != v.UUID.Reveal() || !reflect.DeepEqual(parsed.TLS, v.TLS) || parsed.Security != v.Security || parsed.Name != v.Name {
				t.Fatal("URI semantic loss", err)
			}
			in := testfixture.MieruIntent(t, "tcp")
			in.Inbound.Protocol = module.Key()
			in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{Transport: "tcp", Security: "none", PayloadSecurity: security})
			in.Credentials = in.Credentials[:1]
			in.Bindings = in.Bindings[:1]
			in.Credentials[0].Kind = access.UUID
			in.Credentials[0].Payload = access.UUIDPayload{UUID: v.UUID}
			p, err := (module.Module{}).BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: in.Inbound, Binding: in.Bindings[0], Credential: in.Credentials[0]})
			if err != nil {
				t.Fatal(err)
			}
			p.TLS = v.TLS
			p.Endpoint = v.Endpoint
			p.Metadata["display_name"] = v.Name
			for _, target := range []struct {
				format  ports.Format
				version string
			}{{ports.URI, ""}, {ports.SingBox, "1.14.2"}, {ports.Mihomo, "1.19.32"}} {
				b, err := (exporter.VMess{Target: target.format}).Export(context.Background(), p, ports.ExportTarget{Format: target.format, ClientVersion: target.version})
				if err != nil {
					t.Fatal(err)
				}
				result, err := nodeimport.Parse(string(target.format), b)
				if err != nil || len(result.Issues) > 0 || len(result.Candidates) != 1 {
					t.Fatal("peer import", target.format, err)
				}
				got := result.Candidates[0]
				o, err := module.DecodeClientOptions(got.Node.Options.Data)
				if err != nil || got.Node.Endpoint != v.Endpoint || got.Credential.Value != v.UUID.Reveal() || !reflect.DeepEqual(got.Node.Security.TLS, v.TLS) || o.Security != security || !o.UDP {
					t.Fatal("peer semantic loss", target.format, err)
				}
			}
		}
	}
}
func TestVMessURIBoundsUnsupportedAndNoLossyCA(t *testing.T) {
	valid := `{"v":"2","ps":"synthetic","add":"127.0.0.1","port":"443","id":"` + syntheticUUID + `","aid":"0","scy":"auto","net":"tcp","type":"none","tls":""}`
	if _, err := module.ParseURI(link(valid)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(valid, `"aid":"0"`, `"aid":"64"`, 1), strings.Replace(valid, `"net":"tcp"`, `"net":"ws"`, 1), strings.Replace(valid, `"scy":"auto"`, `"scy":"zero"`, 1), strings.Replace(valid, `"port":"443"`, `"port":"65536"`, 1), strings.Replace(valid, `"port":"443"`, `"port":null`, 1), strings.Replace(valid, `"tls":""`, `"tls":"","fp":"chrome"`, 1), strings.Replace(valid, `"ps":"synthetic"`, `"ps":"bad\nname"`, 1), strings.Replace(valid, `"scy":"auto"`, `"scy":"auto","scy":"none"`, 1), strings.Replace(valid, `"scy":"auto"`, `"scy":"auto","SCY":"none"`, 1), strings.Replace(valid, syntheticUUID, "invalid", 1), strings.Replace(valid, `"net":"tcp"`, `"net":"tcp","path":"/"`, 1),
	} {
		if _, err := module.ParseURI(link(bad)); err == nil {
			t.Fatal("unsupported/malformed URI accepted")
		}
	}
	for _, bad := range []string{"vmess://", "vmess://!", strings.Repeat("A", 4097), link("\xff")} {
		if _, err := module.ParseURI(bad); err == nil {
			t.Fatal("URI bound")
		}
	}
	v := module.URI{Endpoint: access.Endpoint{Host: "localhost", Port: 443}, UUID: secret.New(syntheticUUID), Security: "auto", Name: "Synthetic", TLS: access.ClientTLS{Enabled: true, ServerName: "vmess.synthetic.test", Trust: "explicit_ca", CACertificate: testkit.TLS(t).CACertificate}}
	if _, err := module.EncodeURI(v); err == nil {
		t.Fatal("CA trust lost on export")
	}
}
func TestExternalTLSConflictingFields(t *testing.T) {
	for _, tls := range []string{
		`{"enabled":true,"insecure":true,"Insecure":false}`,
		`{"enabled":false,"Enabled":true}`,
		`{"enabled":true,"insecure":null}`,
		`{"enabled":true,"server_name":null}`,
		`{"enabled":true,"server_name":"first.test","Server_Name":"second.test"}`,
		`{"enabled":true,"reality":null}`,
	} {
		input := []byte(`{"outbounds":[{"type":"vmess","tag":"synthetic","server":"localhost","server_port":443,"uuid":"` + syntheticUUID + `","security":"auto","tls":` + tls + `}]}`)
		got, err := nodeimport.Parse("sing-box", input)
		if err == nil && (len(got.Candidates) != 0 || len(got.Issues) != 1) {
			t.Fatal("conflicting TLS intent accepted")
		}
	}
}

func FuzzVMessURI(f *testing.F) {
	f.Add(link(`{"v":"2","add":"127.0.0.1","port":443,"id":"` + syntheticUUID + `","aid":0,"scy":"auto","net":"tcp"}`))
	f.Add("vmess://")
	for _, seed := range []string{
		`{"aid":1,"aid":0}`, `{"aid":0,"aid":1}`,
		`{"alter_id":64,"ALTER_ID":0}`, `{"ALTER_ID":0,"alter_id":64}`,
		`{"security":"none","Security":"aes-128-cfb"}`,
		`{"transport":"ws","Transport":"tcp"}`, `{"udp":false,"UDP":true}`,
		`{}`, `{"alter_id":0}`, `{"udp":false}`,
		`{"id":"` + syntheticUUID + `","id":"invalid synthetic"}`,
		`{` + strings.Repeat(`"aid":0,`, 2000) + `"aid":1}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// Mutate decoded JSON as well as encoded URIs so base64 validity does
		// not shield duplicate/order/presence mutations from the parser.
		_, _ = module.Decode([]byte(s))
		_, _ = module.DecodeClientOptions([]byte(s))
		_, _ = module.ParseURI(link(s))
		// Preserve a semantic oracle during mutation: arbitrary enum/string
		// content cannot hide a contradictory managed alias in either order.
		value, _ := json.Marshal(s)
		for _, body := range []string{`{"security":"none","Security":` + string(value) + `}`, `{"Security":` + string(value) + `,"security":"none"}`} {
			if s != "none" {
				if _, err := module.DecodeClientOptions([]byte(body)); err == nil {
					t.Fatal("mutated conflicting alias accepted")
				}
			}
		}
		v, err := module.ParseURI(s)
		if err == nil {
			u, err := module.EncodeURI(v)
			if err != nil {
				t.Fatal("export accepted input", err)
			}
			r, err := module.ParseURI(u)
			if err != nil || r.Endpoint != v.Endpoint || r.UUID.Reveal() != v.UUID.Reveal() || r.Security != v.Security || !reflect.DeepEqual(r.TLS, v.TLS) {
				t.Fatal("semantic roundtrip", err)
			}
		}
	})
}
