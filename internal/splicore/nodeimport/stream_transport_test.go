package nodeimport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	tm "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
)

func TestSharedTransportImportExport(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
			for _, format := range []ports.Format{ports.SingBox, ports.Mihomo, ports.URI} {
				t.Run(protocol+"-"+kind+"-"+string(format), func(t *testing.T) {
					id, _ := identity.NewID()
					c := cfg.Config{Kind: kind, Path: "/shared", Host: "transport.synthetic.test"}
					if kind == "grpc" {
						c.Path = ""
						c.Host = ""
						c.ServiceName = "CoreTest"
					}
					p := clientprofile.Profile{ID: id, Schema: 1, Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 24443}, Transport: c, UDPPayload: true, Metadata: identity.Metadata{"display_name": "Synthetic shared transport"}, Options: access.Settings{Schema: 1}}
					p.Credentials = access.UUIDPayload{UUID: secret.New("68f4f564-142b-46b3-8c89-322a37ef1b30")}
					var e ports.Exporter
					version := ""
					switch protocol {
					case "vmess":
						p.Protocol = vm.Key()
						p.Options.Data, _ = json.Marshal(vm.ClientOptions{Security: "auto", UDP: true})
						e = exporter.VMess{Target: format}
						if format == ports.SingBox {
							version = "1.14.2"
						}
						if format == ports.Mihomo {
							version = "1.19.32"
						}
					case "vless":
						p.Protocol = vl.Key(vl.Plain)
						p.Options.Data, _ = json.Marshal(vl.ClientOptions{Security: vl.Plain, Flow: vl.NoFlow, PacketEncoding: "xudp"})
						e = exporter.VLESS{Target: format}
						if format == ports.SingBox {
							version = "1.14.1"
						}
						if format == ports.Mihomo {
							version = "1.19.30"
						}
					case "trojan":
						p.Protocol = tm.Key()
						p.Credentials = access.PasswordPayload{Password: secret.New("SyntheticSharedTransportPassword")}
						p.TLS = access.ClientTLS{Enabled: true, ServerName: "transport.synthetic.test", Trust: "system"}
						p.Options.Data, _ = json.Marshal(tm.ClientOptions{UDP: true})
						e = exporter.Trojan{Target: format}
						if format == ports.SingBox {
							version = "1.14.1"
						}
						if format == ports.Mihomo {
							version = "1.19.30"
						}
					}
					b, err := e.Export(context.Background(), p, ports.ExportTarget{Format: format, ClientVersion: version})
					if err != nil {
						t.Fatal(err)
					}
					var got cfg.Config
					if format == ports.URI {
						v, err := ParseURI(string(b))
						if err != nil {
							t.Fatal(err)
						}
						got = v.Node.Transport
					} else {
						label := "sing-box"
						if format == ports.Mihomo {
							label = "mihomo"
						}
						result, err := Parse(label, b)
						if err != nil || len(result.Candidates) != 1 || len(result.Issues) != 0 {
							t.Fatalf("import failed: %v %+v", err, result.Issues)
						}
						got = result.Candidates[0].Node.Transport
					}
					if !reflect.DeepEqual(c, got) {
						t.Fatalf("transport not preserved: wanted kind=%s path=%s got kind=%s path=%s", c.Kind, c.Path, got.Kind, got.Path)
					}
				})
			}
		}
	}
}
func FuzzSharedTransportImport(f *testing.F) {
	f.Add([]byte(`{"type":"vmess","tag":"synthetic","server":"127.0.0.1","server_port":1234,"uuid":"68f4f564-142b-46b3-8c89-322a37ef1b30","transport":{"type":"ws","path":"/test"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 16384 {
			return
		}
		_, _ = Parse("sing-box", b)
	})
}

func TestSharedTransportFailClosedImport(t *testing.T) {
	base := map[string]any{"type": "vless", "name": "Synthetic", "server": "transport.synthetic.test", "port": 1234, "uuid": "68f4f564-142b-46b3-8c89-322a37ef1b30", "network": "ws", "ws-opts": map[string]any{"path": "/test"}}
	for _, fields := range []map[string]any{
		{"tls": nil}, {"tls": true, "sni": ""}, {"tls": true, "sni": nil}, {"tls": false, "sni": "tls.synthetic.test"},
		{"tls": true, "sni": "one.synthetic.test", "servername": "two.synthetic.test"},
		{"tls": true, "fingerprint": "unsupported-ca-pin"},
		{"ws-opts": map[string]any{"Path": "/alias"}},
		{"ws-opts": map[string]any{"path": "/?ed=12"}},
		{"ws-opts": map[string]any{"max-early-data": 128}},
		{"ws-opts": map[string]any{"headers": map[string]string{"Authorization": "synthetic"}}},
		{"network": "xhttp"}, {"network": "grpc", "grpc-opts": map[string]any{"grpc-service-name": "a/b"}},
	} {
		n := map[string]any{}
		for k, v := range base {
			n[k] = v
		}
		for k, v := range fields {
			n[k] = v
		}
		b, _ := json.Marshal(map[string]any{"proxies": []any{n}})
		r, e := Parse("mihomo", b)
		if e == nil && (len(r.Candidates) != 0 || len(r.Issues) == 0) {
			t.Fatal("unsupported semantics accepted")
		}
	}
	for _, enabled := range []bool{false, true} {
		n := map[string]any{}
		for k, v := range base {
			n[k] = v
		}
		n["tls"] = enabled
		if enabled {
			n["servername"] = "tls.synthetic.test"
		}
		b, _ := json.Marshal(map[string]any{"proxies": []any{n}})
		r, e := Parse("mihomo", b)
		if e != nil || len(r.Candidates) != 1 || len(r.Issues) != 0 {
			t.Fatal("supported TLS bool rejected", e, r.Issues)
		}
		want := "none"
		if enabled {
			want = "tls"
		}
		if r.Candidates[0].Node.Security.Kind != want {
			t.Fatal("TLS downgraded")
		}
	}
}

func TestVMessGRPCSeparatedImport(t *testing.T) {
	input := `{"v":"2","ps":"owned synthetic split","add":"127.0.0.1","port":"24443","id":"68f4f564-142b-46b3-8c89-322a37ef1b30","aid":"0","scy":"auto","net":"grpc","type":"gun","host":"authority.synthetic.test","path":"Review","tls":"tls","sni":"sni.synthetic.test"}`
	a, err := ParseURI("vmess://" + base64.StdEncoding.EncodeToString([]byte(input)))
	if err != nil {
		t.Fatal(err)
	}
	if a.Node.Endpoint.Host != "127.0.0.1" || a.Node.Transport.Host != "authority.synthetic.test" || a.Node.Security.TLS.ServerName != "sni.synthetic.test" {
		t.Fatal("import collapsed identity")
	}
	// External share exporters intentionally reject unrepresentable authority.
	if _, err = vm.EncodeURI(vm.URI{Endpoint: a.Node.Endpoint, UUID: secret.New("68f4f564-142b-46b3-8c89-322a37ef1b30"), Security: "auto", TLS: a.Node.Security.TLS, Name: "synthetic", Transport: a.Node.Transport}); err == nil {
		t.Fatal("unrepresentable export silently dropped authority")
	}
	t.Log("VMess JSON share preserves endpoint/authority/SNI; URI exporter safely rejects explicit gRPC authority; canonical provider/API/backup roundtrip tested separately")
}
