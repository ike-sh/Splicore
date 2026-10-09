//go:build with_quic && with_utls

package application_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	tm "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
)

func TestPhase21SharedProviderAndBackup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("maintenance backup is Linux scoped")
	}
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
			t.Run(protocol+"-"+kind, func(t *testing.T) {
				ctx := context.Background()
				root := t.TempDir()
				path := filepath.Join(root, "original", "state.db")
				s, store := setupProtocols(t, path, nil, registry.NativeCore)
				closed := false
				defer func() {
					if !closed {
						stop(t, s, store)
					}
				}()
				tr := cfg.Config{Kind: kind, Path: "/managed", Host: "core.synthetic.test", Headers: map[string]string{"X-Owned-Fixture": "metadata"}}
				if kind == "grpc" {
					tr.Path = ""
					tr.Host = "authority.synthetic.test"
					tr.Headers = nil
					tr.ServiceName = "ManagedShared"
				}
				serverTr := tr.Clone()
				serverTr.Headers = nil
				if kind == "grpc" {
					// Sing-box export cannot represent an explicit gRPC authority.
					// The synthetic listener accepts the client's independent authority.
					serverTr.Host = ""
				}
				var c expansionCase
				switch protocol {
				case "vmess":
					c = vmessCase(t)
					v := c.settings.(vm.Settings)
					v.Stream = &serverTr
					c.settings = v
				case "trojan":
					c = trojanCase(t)
					v := c.settings.(tm.Settings)
					v.Stream = &serverTr
					c.settings = v
				case "vless":
					for _, a := range expansionCases(t) {
						if a.key.Protocol == "vless" {
							c = a
						}
					}
					v := c.settings.(vl.Settings)
					if kind == "grpc" {
						v.Security = vl.TLS
						v.TLS = vmessCase(t).settings.(vm.Settings).TLS
						c.key = vl.Key(vl.TLS)
					}
					v.Stream = &serverTr
					c.settings = v
				}
				r, e := registry.NewOutbounds(c.factory)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.EnableClientRuntime(ctx, r); e != nil {
					t.Fatal(e)
				}
				port := freePort(t)
				created := expansionCreation(t, s, c, "127.0.0.1", port)
				version := "1.14.1"
				if protocol == "vmess" {
					version = "1.14.2"
				}
				x, e := s.ExportClient(ctx, created.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: version, BindingID: created.Bindings[0].BindingID})
				if e != nil {
					t.Fatal(e)
				}
				parsed, e := nodeimport.Parse("sing-box", []byte(x.Content))
				if e != nil || len(parsed.Candidates) != 1 {
					t.Fatal("server projection", e)
				}
				a := parsed.Candidates[0]
				a.Node.Transport = tr
				if kind == "grpc" && (!a.Node.Security.TLS.Enabled || a.Node.Security.TLS.ServerName == tr.Host) {
					t.Fatal("separated authority/SNI fixture missing")
				}
				// Core API JSON preserves all three identity dimensions.
				encoded, e := json.Marshal(a.Node)
				if e != nil {
					t.Fatal(e)
				}
				nodeCopy := a.Node
				if e = json.Unmarshal(encoded, &nodeCopy); e != nil || !reflect.DeepEqual(a.Node, nodeCopy) {
					t.Fatal("API node round trip", e)
				}
				a.Key = "stable-shared-node"
				a.Node.Name = "Shared synthetic provider"
				// Import preview validates transport intent before any committed state change.
				preview, e := s.PreviewManagement(ctx, application.ManagementRequest{Operation: "import", InputFormat: "canonical", Content: feedDocument([]nodeimport.Candidate{a}), GenerateOutbounds: true})
				if e != nil || !preview.Applicable {
					t.Fatalf("preview err=%v entries=%+v", e, preview.Entries)
				}
				feed := &managementFeed{}
				feed.set(feedDocument([]nodeimport.Candidate{a}), "", 0)
				fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
				defer fixture.Close()
				p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "Shared provider", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: fixture.URL}})
				if _, e = s.RefreshProvider(ctx, p.ProviderID); e != nil {
					t.Fatal(e)
				}
				n := providerNodes(t, s, p.ProviderID)[0]
				if !reflect.DeepEqual(n.Transport, tr) {
					t.Fatal("provider dropped fields")
				}
				if n.Endpoint != a.Node.Endpoint || !reflect.DeepEqual(n.Security, a.Node.Security) {
					t.Fatal("provider changed endpoint/TLS identity")
				}
				status, _ := s.ClientStatus(ctx)
				var oid identity.ID
				for _, o := range status.State.Outbounds {
					if o.NodeID != nil && *o.NodeID == n.ID {
						oid = o.ID
					}
				}
				local := freePort(t)
				addLocal(t, s, local, oid)
				target := echoTarget(t, "127.0.0.1")
				if e = transfer(local, target, []byte("managed shared reply")); e != nil {
					t.Fatal(e)
				}
				a.Node.Name = "Renamed shared provider"
				feed.set(feedDocument([]nodeimport.Candidate{a}), "", 0)
				if _, e = s.RefreshProvider(ctx, p.ProviderID); e != nil {
					t.Fatal(e)
				}
				if providerNodes(t, s, p.ProviderID)[0].ID != n.ID {
					t.Fatal("immutable ID changed")
				}
				before, _ := s.ClientStatus(ctx)
				a.Node.Transport = cfg.Config{Kind: "xhttp"}
				feed.set(feedDocument([]nodeimport.Candidate{a}), "", 0)
				if _, e = s.RefreshProvider(ctx, p.ProviderID); e == nil {
					t.Fatal("unsupported generation accepted")
				}
				after, _ := s.ClientStatus(ctx)
				if !reflect.DeepEqual(before.State.Nodes, after.State.Nodes) || !reflect.DeepEqual(before.State.Outbounds, after.State.Outbounds) {
					t.Fatal("failed generation did not roll back")
				}
				if e = transfer(local, target, []byte("retained shared reply")); e != nil {
					t.Fatal(e)
				}
				// Backup/restore includes full transport fields plus stable encrypted references.
				before, _ = s.ClientStatus(ctx)
				stop(t, s, store)
				closed = true
				backup := filepath.Join(root, "backup", "state.db")
				schema, e := sqlite.MaintenanceBackup(ctx, path, backup)
				if e != nil || schema != 8 {
					t.Fatal("backup", e)
				}
				restored, rs := setupProtocols(t, backup, nil, registry.NativeCore)
				defer stop(t, restored, rs)
				if e = restored.EnableClientRuntime(ctx, r); e != nil {
					t.Fatal(e)
				}
				after, _ = restored.ClientStatus(ctx)
				if !reflect.DeepEqual(before.State, after.State) {
					t.Fatal("backup changed transport or IDs")
				}
				nodes := providerNodes(t, restored, p.ProviderID)
				if len(nodes) != 1 || !reflect.DeepEqual(nodes[0].Transport, tr) {
					t.Fatal("restored transport mismatch")
				}
				credential, e := rs.RevealCredential(ctx, nodes[0].CredentialID)
				if e != nil || credential.Payload == nil {
					t.Fatal("restored encrypted credential", e)
				}
				t.Logf("%s/%s preview/apply/rename/immutable-ID/failed-generation rollback/backup PASS", protocol, kind)
			})
		}
	}
}

func FuzzPhase21ShareFields(f *testing.F) {
	f.Add("ws", "/test", "owned.test", "service")
	f.Fuzz(func(t *testing.T, kind, path, host, service string) {
		if len(kind)+len(path)+len(host)+len(service) > 4096 {
			return
		}
		c := cfg.Config{Kind: kind, Path: path, Host: host, ServiceName: service}
		b, _ := json.Marshal(c)
		var next cfg.Config
		_ = json.Unmarshal(b, &next)
	})
}
