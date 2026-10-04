package nodeimport

import (
	"encoding/base64"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"reflect"
	"strings"
	"testing"
)

const testUUID = "4fa289ef-1d39-4d54-98f9-c4c1d8c98629"

func TestCanonicalCandidateRetainsDocumentSizeContract(t *testing.T) {
	c, err := ParseURI("hy2://synthetic@example.test/?sni=server.test")
	if err != nil {
		t.Fatal(err)
	}
	c.Credential.Value = strings.Repeat("p", 16000)
	c.Node.Options.Data = json.RawMessage(`{"padding":"` + strings.Repeat("x", 1024) + `"}`)
	b, err := json.Marshal(Document{Schema: 1, Nodes: []Candidate{c}})
	if err != nil || len(b) <= provider.MaxLine {
		t.Fatal("invalid size fixture", err)
	}
	r, err := Parse("canonical", b)
	if err != nil || len(r.Candidates) != 1 || len(r.Issues) != 0 {
		t.Fatal("canonical candidate narrowed to URI line limit", err)
	}
}

func TestURIContractsAndStrictInputs(t *testing.T) {
	supported := []string{
		"vless://" + testUUID + "@127.0.0.1:443?encryption=none&type=tcp&security=none&packetEncoding=xudp#same-name",
		"hy2://synthetic%3Apassword@example.test/?sni=server.test&insecure=0#same-name",
		"tuic://" + testUUID + ":synthetic-password@example.test:443?sni=server.test&alpn=h3&congestion_control=cubic&udp_relay_mode=native",
		"mierus://synthetic:synthetic-password@127.0.0.1?profile=fixture&port=443&protocol=TCP&multiplexing=MULTIPLEXING_DEFAULT",
	}
	for _, u := range supported {
		c, e := ParseURI(u)
		if e != nil {
			t.Fatal("supported dialect", e)
		}
		if c.Node.CredentialID != "" || c.Credential.Value == "" {
			t.Fatal("parser assigned ownership")
		}
	}
	unsupportedURIs := []string{
		"snell://synthetic@127.0.0.1:443", "unknown://credential@host",
		"vless://" + testUUID + "@127.0.0.1:443?encryption=none&type=tcp&security=none&packetEncoding=xudp&flow=xtls-rprx-vision",
		"hy2://synthetic@example.test?insecure=1", "hy2://synthetic@example.test?obfs=salamander",
		"tuic://token@example.test:443", "tuic://" + testUUID + ":password@example.test:443?disable_sni=1",
		"mierus://u:p@host?profile=x&port=443&protocol=TCP&handshake-mode=HANDSHAKE_STANDARD",
		"mierus://u:p@host?profile=x&port=443&protocol=TCP&multiplexing=UNKNOWN",
	}
	for i, u := range unsupportedURIs {
		_, e := ParseURI(u)
		if e == nil {
			t.Fatal("unsupported URI accepted", i)
		}
	}
	mixed := supported[0] + "\nunknown://SECRET@host\n"
	r, e := Parse("uri", []byte(mixed))
	if e != nil || len(r.Candidates) != 1 || len(r.Issues) != 1 || r.Issues[0].Kind != "Unsupported" {
		t.Fatal("mixed feed", e)
	}
	b := base64.StdEncoding.EncodeToString([]byte(mixed))
	decoded, e := Parse("base64", []byte(b))
	if e != nil || !reflect.DeepEqual(r, decoded) {
		t.Fatal("base64", e)
	}
	for _, b := range []string{"!!!!", "AA=A", strings.Repeat("A", provider.MaxBody+1)} {
		if _, e := Parse("base64", []byte(b)); e == nil {
			t.Fatal("invalid base64 accepted")
		}
	}
	for _, b := range []string{`{"schema_version":1,"schema_version":1,"nodes":[]}`, `{"schema_version":1,"nodes":[],"server_private_key":"SECRET"}`} {
		if _, e := Parse("canonical", []byte(b)); e == nil {
			t.Fatal("unknown or duplicate field accepted")
		}
	}
}
func TestExternalContractsAndNoSilentExtensions(t *testing.T) {
	inputs := map[string]string{
		"mihomo":   "proxies:\n  - name: snell\n    type: snell\n    server: localhost\n    port: 443\n    version: 6\n    psk: synthetic\n",
		"sing-box": `{"outbounds":[{"type":"tuic","tag":"tuic","server":"localhost","server_port":443,"uuid":"` + testUUID + `","password":"synthetic","tls":{"enabled":true,"server_name":"server.test","alpn":["h3"]}}]}`,
		"mieru":    `{"profiles":[{"profileName":"same-name","user":{"name":"fixture","password":"synthetic"},"servers":[{"ipAddress":"127.0.0.1","portBindings":[{"port":443,"protocol":"TCP"}]}],"mtu":1500,"multiplexing":{"level":"MULTIPLEXING_DEFAULT"}}],"activeProfile":"same-name"}`,
	}
	for format, input := range inputs {
		r, e := Parse(format, []byte(input))
		if e != nil || len(r.Candidates) != 1 || len(r.Issues) != 0 {
			t.Fatal(format, e, r.Issues)
		}
	}
	for _, input := range []string{"payload: &a [x]\nother: *a", "payload: []\npayload: []", "payload: []\n---\npayload: []"} {
		if _, e := YAMLJSON([]byte(input)); e == nil {
			t.Fatal("unsafe YAML accepted")
		}
	}
	r, e := Parse("sing-box", []byte(`{"outbounds":[{"type":"vless","server":"localhost","server_port":443,"uuid":"`+testUUID+`","finalmask":{"tcp":[]}}]}`))
	if e != nil || len(r.Issues) != 1 || len(r.Candidates) > 0 {
		t.Fatal("mask silently ignored")
	}
	if _, e = ParseRules("mihomo-domain", []byte("payload:\n - '+.example.test'\n - exact.test\n")); e != nil {
		t.Fatal(e)
	}
	if _, e = ParseRules("mihomo-classical", []byte("payload:\n - DOMAIN-SUFFIX,example.test\n - IP-CIDR,192.0.2.0/24\n")); e != nil {
		t.Fatal(e)
	}
	if _, e = ParseRules("mihomo-classical", []byte("payload:\n - IP-CIDR,192.0.2.0/24,no-resolve\n")); e == nil {
		t.Fatal("unrepresentable hint discarded")
	}
	if _, e = ParseRules("canonical-rules", []byte(`{"schema_version":1,"rules":[{"rule_sets":["recursive"]}]}`)); e == nil {
		t.Fatal("recursive rule refs")
	}
}
func FuzzURI(f *testing.F) {
	f.Add("hy2://synthetic@example.test?sni=server.test")
	f.Add("mierus://u:p@127.0.0.1?profile=x&port=443&protocol=TCP")
	f.Fuzz(func(t *testing.T, s string) { _, _ = ParseURI(s) })
}
func FuzzFeed(f *testing.F) {
	f.Add("uri", "unknown://synthetic")
	f.Add("base64", "AAAA")
	f.Add("canonical", `{"schema_version":1,"nodes":[]}`)
	f.Add("mihomo", "proxies: []")
	f.Fuzz(func(t *testing.T, format, body string) { _, _ = Parse(format, []byte(body)) })
}
func FuzzFingerprint(f *testing.F) {
	f.Add(`{"name":"display","endpoint":{"host":"example.test","port":443}}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > provider.MaxLine {
			return
		}
		var n client.RemoteNode
		if json.Unmarshal([]byte(raw), &n) != nil {
			return
		}
		before := Fingerprint(n)
		n.Name = "renamed"
		n.ID = "any-id"
		n.CredentialID = "changed-secret-reference"
		n.Tags = []string{"tag"}
		if before != Fingerprint(n) {
			t.Fatal("mutable identity used")
		}
	})
}
func FuzzRules(f *testing.F) {
	f.Add("canonical-rules", `{"schema_version":1,"rules":[]}`)
	f.Add("mihomo-domain", "payload: ['+.example.test']")
	f.Fuzz(func(t *testing.T, format, body string) { _, _ = ParseRules(format, []byte(body)) })
}
