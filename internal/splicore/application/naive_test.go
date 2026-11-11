//go:build with_quic && with_utls

package application_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/naive"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func TestNaiveManagedCreationAccountsBindingRotationAndRestart(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state/state.db"), nil, registry.NativeCore)
			defer stop(t, s, store)
			r, err := registry.NewOutbounds(native.NaiveOutboundFactory{})
			if err != nil {
				t.Fatal(err)
			}
			if err = s.EnableClientRuntime(ctx, r); err != nil {
				t.Fatal(err)
			}
			tls := testkit.TLS(t)
			port := freePort(t)
			if mode == "quic" {
				port = udpPort(t)
			}
			c := expansionCase{"naive", module.Key(), module.Settings{Mode: mode, TLS: tls}, nil, module.Carrier(mode), client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: tls.ServerName, Trust: "explicit_ca", CACertificate: tls.CACertificate}}, native.NaiveOutboundFactory{}}
			c.options, _ = json.Marshal(module.ClientOptions{Mode: mode})
			doc, _ := json.Marshal(map[string]any{"schema": 1, "name": "Naive lifecycle", "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "127.0.0.1", Port: port}, "settings": c.settings, "users": []any{map[string]any{"account_name": "Alpha", "username": "alpha"}, map[string]any{"account_name": "Beta", "username": "beta", "password": "beta-secret"}, map[string]any{"account_name": "Disabled", "username": "disabled", "account_enabled": false}}})
			plan, err := s.PlanCreation(ctx, "naive", doc)
			if err != nil {
				t.Fatal(err)
			}
			created, err := s.ApplyCreation(ctx, "naive", application.ApplyRequest{Document: doc, Digest: plan.Digest, Revision: plan.Revision})
			if err != nil {
				t.Fatal(err)
			}
			target := echoTarget(t, "127.0.0.1")
			var nodes []identity.ID
			var locals []uint16
			for user := range 3 {
				nid := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, expansionCredential(t, store, created, user))
				nodes = append(nodes, nid)
				oid := expansionProxy(t, s, nid, "native")
				local := freePort(t)
				locals = append(locals, local)
				addLocal(t, s, local, oid)
				err := transfer(local, target, []byte("managed Naive TCP"))
				if user == 2 && err == nil {
					t.Fatal("disabled account authenticated")
				}
				if user < 2 && err != nil {
					t.Fatal(err)
				}
				if _, err = s.ExportNodes(ctx, application.NodeExportRequest{IDs: []identity.ID{nid}, Format: "uri", RevealSecrets: true}); err == nil {
					t.Fatal("URI dropped explicit CA")
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
			if transfer(locals[0], target, []byte("disabled binding")) == nil {
				t.Fatal("disabled binding authenticated")
			}
			if err = transfer(locals[1], target, []byte("survivor")); err != nil {
				t.Fatal(err)
			}
			mutate(0, "", true, nil)
			input := application.CredentialInput{Kind: access.UsernamePassword, Value: `{"username":"alpha","password":"rotated-secret"}`}
			mutate(0, "rotate", false, &input)
			if transfer(locals[0], target, []byte("old credential")) == nil {
				t.Fatal("old credential authenticated")
			}
			clientApply(t, s, application.ClientMutation{Resource: "node", Action: "rotate", ID: nodes[0], Credential: &input})
			if err = transfer(locals[0], target, []byte("new credential")); err != nil {
				t.Fatal(err)
			}
			clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
			clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
			if err = transfer(locals[0], target, []byte("restarted client")); err != nil {
				t.Fatal(err)
			}
			mutate(0, "delete", false, nil)
			if transfer(locals[0], target, []byte("deleted")) == nil {
				t.Fatal("deleted authenticated")
			}
			if err = transfer(locals[1], target, []byte("remaining account")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
