package nodeimport_test

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	tr "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	"strings"
	"testing"
)

func TestTrojanPublicTrustExportImport(t *testing.T) {
	id, _ := identity.NewID()
	p := clientprofile.Profile{ID: id, Schema: 1, Protocol: tr.Key(), Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 443}, Credentials: access.PasswordPayload{Password: secret.New("SyntheticImportTrojanPassword")}, TLS: access.ClientTLS{Enabled: true, ServerName: "trojan.synthetic.test", Trust: "system", ALPN: []string{"http/1.1"}}, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: json.RawMessage(`{"udp":true}`)}}
	for _, x := range []struct {
		format  ports.Format
		version string
	}{{ports.URI, ""}, {ports.Mihomo, "1.19.30"}, {ports.SingBox, "1.14.1"}} {
		b, e := (exporter.Trojan{Target: x.format}).Export(context.Background(), p, ports.ExportTarget{Format: x.format, ClientVersion: x.version})
		if e != nil {
			t.Fatal(e)
		}
		v, e := nodeimport.Parse(string(x.format), b)
		if e != nil || len(v.Issues) != 0 || len(v.Candidates) != 1 {
			t.Fatal("roundtrip", e)
		}
		n := v.Candidates[0]
		if n.Node.Protocol != p.Protocol || n.Node.Endpoint != p.Endpoint || n.Node.Security.TLS.Trust != "system" || n.Credential.Value != p.Credentials.(access.PasswordPayload).Password.Reveal() {
			t.Fatal("roundtrip semantic loss")
		}
	}
	v, e := nodeimport.Parse("uri", []byte("trojan://SyntheticImportTrojanPassword@127.0.0.1:443?type=xhttp"))
	if e != nil || len(v.Issues) != 1 || v.Issues[0].Kind != "Unsupported" {
		t.Fatal("unsupported classification lost")
	}
	for _, field := range []string{`"fingerprint":"pin"`, `"client-fingerprint":"chrome"`, `"network":"xhttp"`, `"transport":"ws"`, `"skip-cert-verify":true`, `"method":"aes-128-gcm"`, `"udp":null`} {
		b := []byte(`{"proxies":[{"name":"synthetic","type":"trojan","server":"127.0.0.1","port":443,"password":"SyntheticImportTrojanPassword",` + field + `}]}`)
		v, e := nodeimport.Parse("mihomo", b)
		if e == nil && len(v.Issues) == 0 {
			t.Fatal("security option silently lost", strings.Split(field, ":")[0])
		}
	}
}
