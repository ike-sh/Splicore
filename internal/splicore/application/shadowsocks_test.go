//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	ss "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
)

func enableSS(t *testing.T, s *application.Service, journal ...string) {
	t.Helper()
	r, e := registry.NewOutbounds(native.ShadowsocksOutboundFactory{})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableClientRuntime(context.Background(), r, journal...); e != nil {
		t.Fatal(e)
	}
}
func ssCreation(t *testing.T, s *application.Service, method string, multi bool) application.CreationResult {
	t.Helper()
	port := freePort(t)
	users := []any{map[string]any{"account_name": "SS Alice"}}
	m, _ := ss.Lookup(method)
	if multi || m.Edition == "2017" {
		users = append(users, map[string]any{"account_name": "SS Bob"})
	}
	doc, _ := json.Marshal(map[string]any{"schema": 1, "name": "managed-" + method, "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "127.0.0.1", Port: port}, "settings": ss.Settings{Method: method, MultiUser: multi, UDP: true}, "users": users})
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	c := transport.TestClient(server.Client(), server.URL)
	defer c.Close()
	p, e := c.PlanCreation(context.Background(), "shadowsocks", doc)
	if e != nil {
		t.Fatal(e)
	}
	created, e := c.ApplyCreation(context.Background(), "shadowsocks", application.ApplyRequest{Document: doc, Digest: p.Digest, Revision: p.Revision})
	if e != nil {
		t.Fatal(e)
	}
	return created
}
func ssCandidate(t *testing.T, s *application.Service, created application.CreationResult, user int) nodeimport.Candidate {
	t.Helper()
	export, e := s.ExportClient(context.Background(), created.InboundID, application.ExportRequest{Format: ports.URI, BindingID: created.Bindings[user].BindingID})
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := nodeimport.Parse("uri", []byte(export.Content))
	if e != nil || len(parsed.Candidates) != 1 || len(parsed.Issues) != 0 {
		t.Fatal("URI roundtrip", e)
	}
	c := parsed.Candidates[0]
	c.Key = fmt.Sprintf("synthetic-SS-user-%d", user)
	c.Node.Name = c.Key
	return c
}
func ssImportedOutbound(t *testing.T, s *application.Service, c nodeimport.Candidate) (identity.ID, identity.ID) {
	t.Helper()
	p := managementApply(t, s, application.ManagementRequest{Operation: "import", InputFormat: "canonical", Content: feedDocument([]nodeimport.Candidate{c}), GenerateOutbounds: true})
	nid := p.Entries[0].ID
	status, e := s.ClientStatus(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for _, o := range status.State.Outbounds {
		if o.NodeID != nil && *o.NodeID == nid {
			return nid, o.ID
		}
	}
	t.Fatal("generated proxy missing")
	return "", ""
}
func TestPhase16ShadowsocksManagedMatrix(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableSS(t, s)
	tcp := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "127.0.0.1")
	udp2 := expansionUDP(t, "127.0.0.1")
	for _, m := range ss.Methods() {
		t.Run(m.Name, func(t *testing.T) {
			created := ssCreation(t, s, m.Name, m.Identity)
			var locals []uint16
			for user := range created.Bindings {
				candidate := ssCandidate(t, s, created, user)
				candidate.Key = m.Name + candidate.Key
				candidate.Node.Name = candidate.Key
				nid, oid := ssImportedOutbound(t, s, candidate)
				local := freePort(t)
				addLocal(t, s, local, oid)
				locals = append(locals, local)
				for _, host := range []string{"127.0.0.1", "localhost"} {
					target := tcp
					target.Host = host
					if e := transfer(local, target, bytes.Repeat([]byte("managed-SS"), 8192)); e != nil {
						t.Fatal(e)
					}
				}
				for _, target := range []access.Endpoint{udp, udp2} {
					if e := expansionUDPTraffic(local, target, []byte("managed-UDP")); e != nil {
						t.Fatal(e)
					}
				}
				for _, f := range []struct {
					format  ports.Format
					version string
				}{{ports.SingBox, "1.14.1"}, {ports.Mihomo, "1.19.30"}} {
					x, e := s.ExportNodes(ctx, application.NodeExportRequest{IDs: []identity.ID{nid}, Format: string(f.format), ClientVersion: f.version, RevealSecrets: true})
					if e != nil {
						t.Fatal(e)
					}
					parsed, e := nodeimport.Parse(string(f.format), []byte(x.Content))
					if e != nil || len(parsed.Candidates) != 1 || len(parsed.Issues) != 0 {
						t.Fatal("external profile roundtrip", e)
					}
				}
				status, _ := s.ClientStatus(ctx)
				for _, n := range status.State.Nodes {
					if n.ID == nid {
						n.Name = "renamed " + candidate.Key
						clientApply(t, s, application.ClientMutation{Resource: "node", Action: "update", ID: nid, Node: &n})
					}
				}
				waitIdle(t, s)
			}
			// Disabling A must leave B's credentials and attribution available.
			if len(locals) > 1 {
				view, _ := s.Inbound(ctx, created.InboundID)
				state, _ := store.State(ctx)
				b := created.Bindings[0].BindingID
				var revision identity.Revision
				for _, v := range view.Bindings {
					if v.BindingID == b {
						revision = v.Revision
					}
				}
				if _, e := s.SetBinding(ctx, created.InboundID, application.BindingRequest{BindingID: b, Enabled: false, ResourceRevision: revision, Revision: state.Revision}); e != nil {
					t.Fatal(e)
				}
				if e := transfer(locals[0], tcp, []byte("disabled-A")); e == nil {
					t.Fatal("disabled account authenticated")
				}
				if e := transfer(locals[1], tcp, []byte("unaffected-B")); e != nil {
					t.Fatal(e)
				}
			}
			view, _ := s.Inbound(ctx, created.InboundID)
			for _, b := range view.Bindings {
				if b.Enabled {
					state, _ := store.State(ctx)
					if _, e := s.SetBinding(ctx, created.InboundID, application.BindingRequest{BindingID: b.BindingID, Enabled: false, ResourceRevision: b.Revision, Revision: state.Revision}); e != nil {
						t.Fatal(e)
					}
				}
			}
			view, _ = s.Inbound(ctx, created.InboundID)
			if view.Health != "healthy" {
				t.Fatal("all-disabled listener health", view.Health)
			}
		})
	}
	before, _ := s.ClientStatus(ctx)
	p, e := s.PreviewManagement(ctx, application.ManagementRequest{Operation: "import", InputFormat: "uri", Content: "ss://bad%0Ainput@localhost:1", Mode: "strict"})
	if e != nil || p.Applicable {
		t.Fatal("malformed URI accepted", e)
	}
	after, _ := s.ClientStatus(ctx)
	if before.State.Revision != after.State.Revision {
		t.Fatal("invalid import partially committed")
	}
}
func TestPhase16ShadowsocksProviderRotation(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableSS(t, s)
	created := ssCreation(t, s, "2022-blake3-aes-128-gcm", true)
	a, b := ssCandidate(t, s, created, 0), ssCandidate(t, s, created, 1)
	b.Key = a.Key
	b.Node.Name = a.Node.Name
	feed := &managementFeed{}
	feed.set(feedDocument([]nodeimport.Candidate{a}), "", 0)
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "SS provider", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: fixture.URL}})
	if _, e := s.RefreshProvider(ctx, p.ProviderID); e != nil {
		t.Fatal(e)
	}
	node := providerNodes(t, s, p.ProviderID)[0]
	status, _ := s.ClientStatus(ctx)
	var oid identity.ID
	for _, o := range status.State.Outbounds {
		if o.NodeID != nil && *o.NodeID == node.ID {
			oid = o.ID
		}
	}
	local := freePort(t)
	addLocal(t, s, local, oid)
	target := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "127.0.0.1")
	var wg sync.WaitGroup
	held, e := socksConn(local, target)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	held.SetDeadline(time.Now().Add(10 * time.Second))
	checkHeld := func() {
		payload := []byte("retained SS generation")
		if _, e := held.Write(payload); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, len(payload))
		if _, e := io.ReadFull(held, b); e != nil || !bytes.Equal(b, payload) {
			t.Fatal("held session after replacement", e)
		}
	}
	checkHeld()
	failure := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 20 {
			if e := transfer(local, target, []byte("refresh-race")); e != nil {
				failure <- e
				return
			}
			if e := expansionUDPTraffic(local, udp, []byte("rotation-UDP")); e != nil {
				failure <- e
				return
			}
		}
	}()
	for i := range 10 {
		next := a
		if i%2 == 0 {
			next = b
		}
		next.Node.Name = "renamed provider SS"
		feed.set(feedDocument([]nodeimport.Candidate{next}), "", 0)
		if _, e := s.RefreshProvider(ctx, p.ProviderID); e != nil {
			t.Fatal(e)
		}
		if providerNodes(t, s, p.ProviderID)[0].ID != node.ID {
			t.Fatal("refresh changed immutable ID")
		}
	}
	wg.Wait()
	select {
	case e := <-failure:
		t.Fatal(e)
	default:
	}
	checkHeld()
	held.Close()
	waitIdle(t, s)
	status, _ = s.ClientStatus(ctx)
	generation := status.State.Management.Providers[0].Generation
	feed.set("ss://invalid", "", 0)
	if _, e := s.RefreshProvider(ctx, p.ProviderID); e == nil {
		t.Fatal("invalid refresh accepted")
	}
	status, _ = s.ClientStatus(ctx)
	if status.State.Management.Providers[0].Generation != generation {
		t.Fatal("failed refresh replaced generation")
	}
	if e := transfer(local, target, []byte("retained committed SS")); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{a.Credential.Value, b.Credential.Value} {
		doctor, _ := s.Doctor(ctx, "test")
		raw, _ := json.Marshal(doctor)
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("doctor leaked credential")
		}
		raw, _ = json.Marshal(status)
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("status leaked credential")
		}
	}
}

func TestPhase16ShadowsocksListenerConflict(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	port := freePort(t)
	occupied, e := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	doc, _ := json.Marshal(map[string]any{"schema": 1, "name": "conflicting-SS", "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "127.0.0.1", Port: port}, "settings": ss.Settings{Method: "aes-128-gcm", UDP: true}, "users": []any{map[string]any{"account_name": "synthetic"}}})
	p, e := s.PlanCreation(ctx, "shadowsocks", doc)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ApplyCreation(ctx, "shadowsocks", application.ApplyRequest{Document: doc, Digest: p.Digest, Revision: p.Revision}); e == nil {
		t.Fatal("occupied UDP activated")
	}
	page, e := s.Inbounds(ctx)
	if e != nil || len(page.Items) != 0 {
		t.Fatal("partial domain commit", e)
	}
	state, e := store.State(ctx)
	if e != nil || state.PendingTransactions != 0 {
		t.Fatal("dangling operation", e)
	}
	l, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if e != nil {
		t.Fatal("half-active TCP listener", e)
	}
	l.Close()
}
