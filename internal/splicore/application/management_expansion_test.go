//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase14ImportAllProtocolsTraffic(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, phase8Protocols)
	defer stop(t, s, store)
	cases := expansionCases(t)
	factories := []ports.OutboundFactory{}
	for _, c := range cases {
		factories = append(factories, c.factory)
	}
	r, e := registry.NewOutbounds(factories...)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableClientRuntime(ctx, r); e != nil {
		t.Fatal(e)
	}
	target := echoTarget(t, "127.0.0.1")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			remote := freePort(t)
			if c.transport == "quic" {
				remote = udpPort(t)
			}
			created := expansionCreation(t, s, c, "127.0.0.1", remote)
			credential := expansionCredential(t, store, created, 0)
			input := payloadInput(credential)
			candidate := nodeimport.Candidate{Node: client.RemoteNode{Name: "DIRECT", Protocol: c.key, Endpoint: access.Endpoint{Host: "127.0.0.1", Port: remote}, Transport: client.Transport{Kind: c.transport}, Security: c.security, Options: client.Options{Schema: 1, Data: c.options}}, Credential: nodeimport.Credential{Kind: input.Kind, Value: input.Value}}
			document := feedDocument([]nodeimport.Candidate{candidate})
			format := "canonical"
			if c.name == "vless" {
				format = "uri"
				document = "vless://" + credential.(access.UUIDPayload).UUID.Reveal() + "@" + net.JoinHostPort("127.0.0.1", fmt.Sprint(remote)) + "?encryption=none&type=tcp&security=none&packetEncoding=xudp#DIRECT"
			}
			if c.name == "mieru" {
				format = "uri"
				pair := credential.(access.UsernamePasswordPayload)
				u := url.URL{Scheme: "mierus", User: url.UserPassword(pair.Username.Reveal(), pair.Password.Reveal()), Host: "127.0.0.1", RawQuery: url.Values{"profile": {"DIRECT"}, "port": {fmt.Sprint(remote)}, "protocol": {"TCP"}}.Encode()}
				document = u.String()
			}
			p := managementApply(t, s, application.ManagementRequest{Operation: "import", InputFormat: format, Content: document, GenerateOutbounds: true})
			nid := p.Entries[len(p.Entries)-1].ID
			status, e := s.ClientStatus(ctx)
			if e != nil {
				t.Fatal(e)
			}
			oid := status.State.Outbounds[len(status.State.Outbounds)-1].ID
			for _, o := range status.State.Outbounds {
				if o.NodeID != nil && *o.NodeID == nid {
					oid = o.ID
				}
			}
			local := freePort(t)
			addLocal(t, s, local, oid)
			if e = transfer(local, target, bytes.Repeat([]byte("Phase14-import-"+c.name), 2048)); e != nil {
				t.Fatal("import traffic", e)
			}
			waitIdle(t, s)
			exported, e := s.ExportNodes(ctx, application.NodeExportRequest{IDs: []identity.ID{nid}, Format: "canonical", RevealSecrets: true})
			if e != nil {
				t.Fatal(e)
			}
			if c.name == "mieru" {
				external, err := s.ExportNodes(ctx, application.NodeExportRequest{IDs: []identity.ID{nid}, Format: "mieru", ClientVersion: "3.38.0", RevealSecrets: true})
				if err != nil {
					t.Fatal("Mieru client config export", err)
				}
				parsed, err := nodeimport.Parse("mieru", []byte(external.Content))
				if err != nil || len(parsed.Candidates) != 1 {
					t.Fatal("Mieru config reimport", err)
				}
			}
			reimport, e := s.PreviewManagement(ctx, application.ManagementRequest{Operation: "import", InputFormat: "canonical", Content: exported.Content})
			if e != nil || !reimport.Applicable || reimport.Entries[0].Kind != "Unchanged" {
				t.Fatal("canonical reimport", e, reimport.Reason)
			}
			managementApply(t, s, application.ManagementRequest{Operation: "batch", Action: "disable", IDs: []identity.ID{nid}})
			if e = transfer(local, target, []byte("disabled")); e == nil {
				t.Fatal("disabled node selected")
			}
			waitIdle(t, s)
			managementApply(t, s, application.ManagementRequest{Operation: "batch", Action: "enable", IDs: []identity.ID{nid}})
			if e = transfer(local, target, []byte("enabled")); e != nil {
				t.Fatal(e)
			}
			waitIdle(t, s)
			invalid := strings.Replace(document, "packetEncoding=xudp", "packetEncoding=xudp&flow=xtls-rprx-vision", 1)
			if c.name == "vless" {
				p, e = s.PreviewManagement(ctx, application.ManagementRequest{Operation: "import", InputFormat: "uri", Content: invalid})
				if e != nil || p.Applicable {
					t.Fatal("Vision accepted", e)
				}
			}
		})
	}
	// Explicit strict/lenient previews have no DB effects and never print raw input.
	p, e := s.PreviewManagement(ctx, application.ManagementRequest{Operation: "import", InputFormat: "uri", Content: "unknown://SECRET@host", Mode: "strict"})
	if e != nil || p.Applicable {
		t.Fatal("strict unsupported")
	}
	p, e = s.PreviewManagement(ctx, application.ManagementRequest{Operation: "import", InputFormat: "uri", Content: "unknown://SECRET@host", Mode: "lenient"})
	if e != nil || !p.Applicable || len(p.Entries) != 1 {
		t.Fatal("lenient explicit issue", e)
	}
	b, _ := json.Marshal(p)
	if bytes.Contains(b, []byte("SECRET")) {
		t.Fatal("error secret")
	}
}
