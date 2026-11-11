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

// Keep the original flow/enable assertions and expose a failed native dial's
// cause in the owned test fixture, rather than losing it behind SOCKS reply 1.
type phase14DiagnosticFactory struct {
	ports.OutboundFactory
	t *testing.T
}

func (f phase14DiagnosticFactory) Build(ctx context.Context, node client.RemoteNode, credential access.Credential) (ports.ClientDialer, error) {
	d, err := f.OutboundFactory.Build(ctx, node, credential)
	if err != nil {
		return nil, err
	}
	return &phase14DiagnosticDialer{ClientDialer: d, t: f.t}, nil
}

type phase14DiagnosticDialer struct {
	ports.ClientDialer
	t *testing.T
}

func (d *phase14DiagnosticDialer) DialContext(ctx context.Context, target access.Endpoint) (net.Conn, error) {
	c, err := d.ClientDialer.DialContext(ctx, target)
	if err != nil {
		d.t.Logf("TUIC native dial failed: type=%T cause=%v context=%v", err, err, ctx.Err())
	}
	return c, err
}

func (d *phase14DiagnosticDialer) ListenPacket(ctx context.Context, target access.Endpoint) (net.PacketConn, error) {
	return d.ClientDialer.(ports.ClientPacketDialer).ListenPacket(ctx, target)
}

func (d *phase14DiagnosticDialer) SupportsNetwork(network string) bool {
	if support, ok := d.ClientDialer.(ports.ClientNetworkSupport); ok {
		return support.SupportsNetwork(network)
	}
	return network == "tcp" || network == "udp"
}

func TestPhase14ImportAllProtocolsTraffic(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, phase8Protocols)
	defer stop(t, s, store)
	cases := expansionCases(t)
	factories := []ports.OutboundFactory{}
	for _, c := range cases {
		factory := c.factory
		if c.name == "tuic" {
			factory = phase14DiagnosticFactory{factory, t}
		}
		factories = append(factories, factory)
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
