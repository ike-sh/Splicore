package sqlite

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

func TestManagedSOCKS5CommittedAdmission(t *testing.T) {
	ctx := t.Context()
	modules, _, _, err := registry.NativeCore()
	if err != nil {
		t.Fatal(err)
	}
	opts := options(t)
	opts.ValidateInbound = (proxy.SOCKS5Inbound{}).ValidateInbound
	opts.CredentialKinds = func(key access.ProtocolKey) ([]access.CredentialKind, error) {
		module, err := modules.Get(key)
		if err != nil {
			return nil, err
		}
		return module.Metadata().CredentialKinds, nil
	}
	s, err := Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	state, err := s.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := account(t)
	stamp := identity.NewStamp(time.Now())
	endpoint := access.Endpoint{Host: "127.0.0.1", Port: 1080}
	in := access.Inbound{ID: newID(t), NodeID: state.NodeID, Name: "SOCKS5 admission fixture", Protocol: proxy.Key("socks5"), Engine: "native", Enabled: true,
		Listeners:        []access.Listener{{ID: newID(t), Transport: "tcp", Endpoint: endpoint}},
		DisplayEndpoints: []access.DisplayEndpoint{{ID: newID(t), Endpoint: endpoint}},
		Settings:         access.Settings{Schema: 1, Data: []byte(`{"auth":true}`)}, Stamp: stamp}
	c := access.Credential{ID: newID(t), OwnerAccountID: &a.ID, Kind: access.UsernamePassword, Schema: 1, State: "active", Stamp: stamp,
		Payload: access.UsernamePasswordPayload{Username: secret.New("alice"), Password: secret.New("Synthetic-SQLite-Fixture!73")}}
	b := access.Binding{ID: newID(t), AccountID: a.ID, InboundID: in.ID, CredentialID: c.ID, Enabled: true, Stamp: stamp}
	if _, err := s.Transact(ctx, state.Revision, actor(t), func(w ports.Writer) error {
		if err := w.CreateAccount(a); err != nil {
			return err
		}
		if err := w.CreateInbound(in); err != nil {
			return err
		}
		if err := w.CreateCredential(c); err != nil {
			return err
		}
		return w.CreateBinding(b)
	}); err != nil {
		t.Fatal(err)
	}
	if !s.BindingAllowed(ctx, b) {
		t.Fatal("active committed binding was denied")
	}
	forged := b
	forged.AccountID = newID(t)
	if s.BindingAllowed(ctx, forged) {
		t.Fatal("unrelated account was admitted")
	}
	for _, test := range []struct {
		name, change, reset string
		id                  identity.ID
	}{
		{"disabled account", "UPDATE accounts SET enabled=0 WHERE id=?", "UPDATE accounts SET enabled=1 WHERE id=?", a.ID},
		{"expired account", "UPDATE accounts SET expires_at='2001-01-01T00:00:00Z' WHERE id=?", "UPDATE accounts SET expires_at=NULL WHERE id=?", a.ID},
		{"revoked credential", "UPDATE credentials SET state='revoked' WHERE id=?", "UPDATE credentials SET state='active' WHERE id=?", c.ID},
		{"disabled binding", "UPDATE bindings SET enabled=0 WHERE id=?", "UPDATE bindings SET enabled=1 WHERE id=?", b.ID},
		{"stopped inbound", "UPDATE inbounds SET enabled=0 WHERE id=?", "UPDATE inbounds SET enabled=1 WHERE id=?", in.ID},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := s.db.ExecContext(ctx, test.change, test.id); err != nil {
				t.Fatal(err)
			}
			if s.BindingAllowed(ctx, b) {
				t.Error("stale runtime binding was admitted against committed state")
			}
			if _, err := s.db.ExecContext(ctx, test.reset, test.id); err != nil {
				t.Fatal(err)
			}
			if !s.BindingAllowed(ctx, b) {
				t.Fatal("active binding was denied after fixture reset")
			}
		})
	}
}
