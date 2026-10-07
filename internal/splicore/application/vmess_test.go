//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	tr "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
)

func vmessCase(t *testing.T) expansionCase {
	t.Helper()
	tls := testkit.TLSForName(t, "vmess.synthetic.test")
	return expansionCase{"vmess", tr.Key(), tr.Settings{Transport: "tcp", Security: "tls", PayloadSecurity: "auto", TLS: &tls}, []byte(`{"udp":true}`), "tcp", client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: tls.ServerName, Trust: "explicit_ca", CACertificate: tls.CACertificate}}, native.VMessOutboundFactory{}}
}
func enableVMess(t *testing.T, s *application.Service, journal ...string) {
	t.Helper()
	r, e := registry.NewOutbounds(native.VMessOutboundFactory{})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableClientRuntime(context.Background(), r, journal...); e != nil {
		t.Fatal(e)
	}
}
func vmessCreation(t *testing.T, s *application.Service) application.CreationResult {
	t.Helper()
	c := vmessCase(t)
	port := freePort(t)
	doc, _ := json.Marshal(map[string]any{"schema": 1, "name": "managed-VMess", "engine": "native", "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "127.0.0.1", Port: port}, "settings": c.settings, "users": []any{map[string]any{"account_name": "VMess Alice"}, map[string]any{"account_name": "VMess Bob"}}})
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	ctl := transport.TestClient(server.Client(), server.URL)
	defer ctl.Close()
	p, e := ctl.PlanCreation(context.Background(), "vmess", doc)
	if e != nil {
		t.Fatal(e)
	}
	created, e := ctl.ApplyCreation(context.Background(), "vmess", application.ApplyRequest{Document: doc, Digest: p.Digest, Revision: p.Revision})
	if e != nil {
		t.Fatal(e)
	}
	return created
}
func vmessCandidate(t *testing.T, s *application.Service, created application.CreationResult, user int) nodeimport.Candidate {
	t.Helper()
	x, e := s.ExportClient(context.Background(), created.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.2", BindingID: created.Bindings[user].BindingID})
	if e != nil {
		t.Fatal(e)
	}
	p, e := nodeimport.Parse("sing-box", []byte(x.Content))
	if e != nil || len(p.Candidates) != 1 || len(p.Issues) != 0 {
		t.Fatal("VMess CA profile roundtrip", e)
	}
	c := p.Candidates[0]
	c.Key = fmt.Sprintf("VMess-user-%d", user)
	c.Node.Name = c.Key
	return c
}

func TestPhase19VMessManagedUsersAndRotation(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableVMess(t, s)
	created := vmessCreation(t, s)
	tcp := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "127.0.0.1")
	udp2 := expansionUDP(t, "127.0.0.1")
	locals := []uint16{}
	ids := []identity.ID{}
	for user := range 2 {
		c := vmessCandidate(t, s, created, user)
		nid, oid := ssImportedOutbound(t, s, c)
		ids = append(ids, nid)
		local := freePort(t)
		addLocal(t, s, local, oid)
		locals = append(locals, local)
		for _, host := range []string{"127.0.0.1", "localhost"} {
			target := tcp
			target.Host = host
			if e := transfer(local, target, bytes.Repeat([]byte("VMess-TCP"), 8192)); e != nil {
				t.Fatal(e)
			}
		}
		for _, target := range []access.Endpoint{udp, udp2} {
			if e := expansionUDPTraffic(local, target, []byte("VMess-UDP")); e != nil {
				t.Fatal(e)
			}
		}
		for _, f := range []struct {
			format  ports.Format
			version string
		}{{ports.SingBox, "1.14.2"}} {
			x, e := s.ExportNodes(ctx, application.NodeExportRequest{IDs: []identity.ID{nid}, Format: string(f.format), ClientVersion: f.version, RevealSecrets: true})
			if e != nil {
				t.Fatal(e)
			}
			if f.format == ports.SingBox {
				p, e := nodeimport.Parse("sing-box", []byte(x.Content))
				if e != nil || len(p.Candidates) != 1 || len(p.Issues) != 0 {
					t.Fatal("node export lost CA")
				}
			}
		}
		if _, e := s.ExportNodes(ctx, application.NodeExportRequest{IDs: []identity.ID{nid}, Format: "uri", RevealSecrets: true}); e == nil {
			t.Fatal("URI silently dropped explicit CA")
		}
	}
	mutate := func(user int, action string, enabled bool, input *application.CredentialInput) {
		t.Helper()
		v, e := s.Inbound(ctx, created.InboundID)
		if e != nil {
			t.Fatal(e)
		}
		state, _ := store.State(ctx)
		for _, b := range v.Bindings {
			if b.BindingID == created.Bindings[user].BindingID {
				server := httptest.NewServer(api.Handler(s))
				defer server.Close()
				ctl := transport.TestClient(server.Client(), server.URL)
				defer ctl.Close()
				if _, e = ctl.SetBinding(ctx, created.InboundID, application.BindingRequest{BindingID: b.BindingID, Action: action, Enabled: enabled, Credential: input, ResourceRevision: b.Revision, Revision: state.Revision}); e != nil {
					t.Fatal(e)
				}
				return
			}
		}
		t.Fatal("missing binding")
	}
	mutate(0, "", false, nil)
	if e := transfer(locals[0], tcp, []byte("disabled")); e == nil {
		t.Fatal("disabled user authenticated")
	}
	if e := transfer(locals[1], tcp, []byte("B survives generation replacement")); e != nil {
		t.Fatal(e)
	}
	mutate(0, "", true, nil)
	mutate(0, "rotate", false, &application.CredentialInput{Kind: access.UUID, Value: "00000000-0000-3000-8000-000000000003"})
	if e := transfer(locals[0], tcp, []byte("old password")); e == nil {
		t.Fatal("old credential authenticated")
	}
	c := vmessCandidate(t, s, created, 0)
	status, _ := s.ClientStatus(ctx)
	for _, n := range status.State.Nodes {
		if n.ID == ids[0] {
			input := application.CredentialInput{Kind: access.UUID, Value: c.Credential.Value}
			clientApply(t, s, application.ClientMutation{Resource: "node", Action: "rotate", ID: n.ID, Credential: &input})
		}
	}
	if e := transfer(locals[0], tcp, []byte("new password")); e != nil {
		t.Fatal(e)
	}
	if e := transfer(locals[1], tcp, []byte("B after rotation")); e != nil {
		t.Fatal(e)
	}
	mutate(0, "delete", false, nil)
	if e := transfer(locals[0], tcp, []byte("deleted")); e == nil {
		t.Fatal("deleted user authenticated")
	}
	if e := transfer(locals[1], tcp, []byte("B after deletion")); e != nil {
		t.Fatal(e)
	}
	v, _ := s.Inbound(ctx, created.InboundID)
	if len(v.Bindings) != 1 {
		t.Fatal("user deletion retained binding")
	}
	if _, e := store.Account(ctx, created.Bindings[0].AccountID); e == nil {
		t.Fatal("deleted account retained")
	}
	p, e := s.PreviewManagement(ctx, application.ManagementRequest{Operation: "batch", Action: "delete", IDs: []identity.ID{ids[1]}})
	if e != nil || p.Applicable || p.Reason != "referenced_node" {
		t.Fatal("referenced VMess node deletion", e)
	}
}

func TestPhase19VMessUserReferenceRollback(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableVMess(t, s)
	created := vmessCreation(t, s)
	candidate := vmessCandidate(t, s, created, 1)
	_, oid := ssImportedOutbound(t, s, candidate)
	local := freePort(t)
	addLocal(t, s, local, oid)
	tcp := echoTarget(t, "127.0.0.1")
	bs, e := store.Bindings(ctx, created.InboundID)
	if e != nil {
		t.Fatal(e)
	}
	var original access.Binding
	for _, b := range bs {
		if b.ID == created.Bindings[0].BindingID {
			original = b
		}
	}
	duplicate := original
	duplicate.ID, _ = identity.NewID()
	duplicate.Stamp = identity.NewStamp(time.Now())
	duplicate.Enabled = false
	view, e := s.Inbound(ctx, created.InboundID)
	if e != nil {
		t.Fatal(e)
	}
	other := view.Inbound
	other.ID, _ = identity.NewID()
	other.Stamp = identity.NewStamp(time.Now())
	other.Name = "synthetic reference owner"
	duplicate.InboundID = other.ID
	other.Listeners[0].Endpoint.Port = freePort(t)
	other.Listeners[0].ID, _ = identity.NewID()
	other.DisplayEndpoints[0].ID, _ = identity.NewID()
	other.DisplayEndpoints[0].Endpoint = other.Listeners[0].Endpoint
	state, _ := store.State(ctx)
	actor := identity.Actor{Principal: "local", RequestID: duplicate.ID}
	if _, e = store.Transact(ctx, state.Revision, actor, func(w ports.Writer) error {
		if e := w.CreateInbound(other); e != nil {
			return e
		}
		return w.CreateBinding(duplicate)
	}); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"delete", "rotate"} {
		state, _ = store.State(ctx)
		req := application.BindingRequest{Action: action, BindingID: original.ID, ResourceRevision: original.Revision, Revision: state.Revision}
		if action == "rotate" {
			req.Credential = &application.CredentialInput{Kind: access.UUID, Value: "00000000-0000-3000-8000-000000000004"}
		}
		if _, e = s.SetBinding(ctx, created.InboundID, req); e == nil {
			t.Fatal("cross-binding user mutation accepted")
		}
		after, _ := store.State(ctx)
		if after.Revision != state.Revision || after.PendingTransactions != 0 {
			t.Fatal("failed user mutation committed")
		}
		if e = transfer(local, tcp, []byte("B after failed user mutation rollback")); e != nil {
			t.Fatal(e)
		}
		if _, e = store.Account(ctx, original.AccountID); e != nil {
			t.Fatal("referenced account removed")
		}
	}
}
