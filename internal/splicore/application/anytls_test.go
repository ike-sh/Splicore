//go:build with_quic && with_utls

package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/anytls"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func TestAnyTLSManagedCreationUsersRotationAndURI(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state/state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	r, err := registry.NewOutbounds(native.AnyTLSOutboundFactory{})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(ctx, r); err != nil {
		t.Fatal(err)
	}
	tls := testkit.TLSForName(t, "anytls.synthetic.test")
	c := expansionCase{"anytls", module.Key(), module.Settings{TLS: tls}, []byte(`{"udp":true}`), "tcp", client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: tls.ServerName, Trust: "explicit_ca", CACertificate: tls.CACertificate}}, native.AnyTLSOutboundFactory{}}
	port := freePort(t)
	created := expansionCreation(t, s, c, "127.0.0.1", port)
	tcp := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "127.0.0.1")
	var nodes []identity.ID
	var locals []uint16
	for user := range 2 {
		nid := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, expansionCredential(t, store, created, user))
		nodes = append(nodes, nid)
		oid := expansionProxy(t, s, nid, "native")
		local := freePort(t)
		locals = append(locals, local)
		addLocal(t, s, local, oid)
		if err = transfer(local, tcp, []byte("managed AnyTLS TCP")); err != nil {
			t.Fatal(err)
		}
		if err = expansionUDPTraffic(local, udp, []byte("managed AnyTLS UDP")); err != nil {
			t.Fatal(err)
		}
		x, err := s.ExportClient(ctx, created.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.2", BindingID: created.Bindings[user].BindingID})
		if err != nil {
			t.Fatal(err)
		}
		var exported map[string]any
		if json.Unmarshal([]byte(x.Content), &exported) != nil || exported["type"] != "anytls" {
			t.Fatal("sing-box export")
		}
		ca := exported["tls"].(map[string]any)["certificate"].([]any)
		if len(ca) != 1 || ca[0] != tls.CACertificate {
			t.Fatal("CA export loss")
		}
		if _, err = s.ExportNodes(ctx, application.NodeExportRequest{IDs: []identity.ID{nid}, Format: "uri", RevealSecrets: true}); err == nil {
			t.Fatal("URI silently dropped CA")
		}
	}
	mutate := func(user int, action string, enabled bool, input *application.CredentialInput) {
		t.Helper()
		v, err := s.Inbound(ctx, created.InboundID)
		if err != nil {
			t.Fatal(err)
		}
		state, _ := store.State(ctx)
		for _, b := range v.Bindings {
			if b.BindingID == created.Bindings[user].BindingID {
				_, err = s.SetBinding(ctx, created.InboundID, application.BindingRequest{BindingID: b.BindingID, Action: action, Enabled: enabled, Credential: input, ResourceRevision: b.Revision, Revision: state.Revision})
				if err != nil {
					t.Fatal(err)
				}
				return
			}
		}
		t.Fatal("missing binding")
	}
	mutate(0, "", false, nil)
	if transfer(locals[0], tcp, []byte("disabled")) == nil {
		t.Fatal("disabled authenticated")
	}
	if err = transfer(locals[1], tcp, []byte("survivor")); err != nil {
		t.Fatal(err)
	}
	mutate(0, "", true, nil)
	mutate(0, "rotate", false, &application.CredentialInput{Kind: access.Password, Value: "SyntheticRotatedAnyTLSPassword"})
	if transfer(locals[0], tcp, []byte("old credential")) == nil {
		t.Fatal("old credential authenticated")
	}
	input := payloadInput(expansionCredential(t, store, created, 0))
	clientApply(t, s, application.ClientMutation{Resource: "node", Action: "rotate", ID: nodes[0], Credential: &input})
	if err = transfer(locals[0], tcp, []byte("new credential")); err != nil {
		t.Fatal(err)
	}
	if err = transfer(locals[1], tcp, []byte("second user after rotation")); err != nil {
		t.Fatal(err)
	}
	// Exercise the common URI import/export path with an explicit test-only
	// insecure option because this URI cannot contain the local private CA.
	uri := fmt.Sprintf("anytls://%s@127.0.0.1:%d/?sni=%s&insecure=1#URI%%20node", input.Value, port, tls.ServerName)
	parsed, err := nodeimport.Parse("uri", []byte(uri))
	if err != nil || len(parsed.Candidates) != 1 || len(parsed.Issues) != 0 {
		t.Fatal("URI import", err)
	}
	nid, oid := ssImportedOutbound(t, s, parsed.Candidates[0])
	local := freePort(t)
	addLocal(t, s, local, oid)
	if err = transfer(local, tcp, []byte("explicit insecure URI localhost")); err != nil {
		t.Fatal(err)
	}
	x, err := s.ExportNodes(ctx, application.NodeExportRequest{IDs: []identity.ID{nid}, Format: "uri", RevealSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	again, err := nodeimport.Parse("uri", []byte(x.Content))
	if err != nil || len(again.Candidates) != 1 || again.Candidates[0].Credential.Value != input.Value {
		t.Fatal("URI roundtrip", err)
	}
	mutate(0, "delete", false, nil)
	if transfer(locals[0], tcp, []byte("deleted")) == nil {
		t.Fatal("deleted authenticated")
	}
	if err = transfer(locals[1], tcp, []byte("second user after deletion")); err != nil {
		t.Fatal(err)
	}
}

func TestAnyTLSDisabledAccountCreation(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state/state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	r, err := registry.NewOutbounds(native.AnyTLSOutboundFactory{})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(ctx, r); err != nil {
		t.Fatal(err)
	}
	tls := testkit.TLSForName(t, "anytls.synthetic.test")
	port := freePort(t)
	c := expansionCase{"anytls", module.Key(), module.Settings{TLS: tls}, []byte(`{"udp":true}`), "tcp", client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: tls.ServerName, Trust: "explicit_ca", CACertificate: tls.CACertificate}}, native.AnyTLSOutboundFactory{}}
	doc, _ := json.Marshal(map[string]any{"schema": 1, "name": "disabled account snapshot", "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "127.0.0.1", Port: port}, "settings": c.settings, "users": []any{map[string]any{"account_name": "Disabled", "account_enabled": false}, map[string]any{"account_name": "Enabled"}}})
	plan, err := s.PlanCreation(ctx, "anytls", doc)
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.ApplyCreation(ctx, "anytls", application.ApplyRequest{Document: doc, Digest: plan.Digest, Revision: plan.Revision})
	if err != nil {
		t.Fatal(err)
	}
	target := echoTarget(t, "127.0.0.1")
	for user := range 2 {
		n := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, expansionCredential(t, store, created, user))
		o := expansionProxy(t, s, n, "native")
		local := freePort(t)
		addLocal(t, s, local, o)
		err := transfer(local, target, []byte("account eligibility"))
		if user == 0 && err == nil {
			t.Fatal("disabled account authenticated")
		}
		if user == 1 && err != nil {
			t.Fatal(err)
		}
	}
}
