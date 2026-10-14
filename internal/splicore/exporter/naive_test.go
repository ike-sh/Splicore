package exporter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/naive"
)

func TestNaiveURIExportImportRoundTripAndLossRejection(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			id, _ := identity.NewID()
			payload := access.UsernamePasswordPayload{Username: secret.New("user@x"), Password: secret.New("Synthetic:p@ss")}
			options, _ := json.Marshal(module.ClientOptions{Mode: mode})
			p := clientprofile.Profile{ID: id, Schema: 1, Protocol: module.Key(), Endpoint: access.Endpoint{Host: "::1", Port: 443}, Credentials: payload, TLS: access.ClientTLS{Enabled: true, ServerName: "::1", Trust: "system", ALPN: []string{module.ALPN(mode)}}, Transport: clientprofile.Transport{Kind: module.Carrier(mode)}, Options: access.Settings{Schema: 1, Data: options}, Metadata: identity.Metadata{"display_name": "测试 node"}}
			e := exporter.Naive{Target: ports.URI}
			target := ports.ExportTarget{Format: ports.URI}
			u, err := e.Export(context.Background(), p, target)
			if err != nil {
				t.Fatal(err)
			}
			r, err := nodeimport.Parse("uri", u)
			if err != nil || len(r.Candidates) != 1 || len(r.Issues) != 0 {
				t.Fatal("import", err)
			}
			var pair map[string]string
			json.Unmarshal([]byte(r.Candidates[0].Credential.Value), &pair)
			if pair["username"] != payload.Username.Reveal() || pair["password"] != payload.Password.Reveal() || r.Candidates[0].Node.Endpoint != p.Endpoint || r.Candidates[0].Node.Transport.Kind != p.Transport.Kind {
				t.Fatal("roundtrip loss")
			}
			if strings.Contains(fmt.Sprintf("%+v", r.Candidates[0]), payload.Password.Reveal()) {
				t.Fatal("secret in diagnostics")
			}
			original := p.TLS
			p.TLS.Trust = "explicit_ca"
			p.TLS.CACertificate = "not-a-real-CA"
			if _, err = e.Export(context.Background(), p, target); err == nil {
				t.Fatal("CA dropped")
			}
			p.TLS = original
			for _, raw := range []string{`{"mode":"` + mode + `","padding":"off"}`, `{"mode":"` + mode + `","max_connections":2}`, `{"mode":"` + mode + `","extra_headers":{"X-Test":"v"}}`, `{"mode":"` + mode + `","idle_timeout":"1m"}`} {
				p.Options.Data = []byte(raw)
				if _, err = e.Export(context.Background(), p, target); err == nil {
					t.Fatal("options dropped")
				}
			}
		})
	}
}
