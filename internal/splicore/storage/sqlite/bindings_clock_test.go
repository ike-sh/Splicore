package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func clockBinding(t *testing.T, s *Store, stamp identity.Stamp) access.Binding {
	t.Helper()
	ctx := context.Background()
	state, err := s.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := account(t)
	i := access.Inbound{
		ID: newID(t), NodeID: state.NodeID, Name: "binding clock fixture",
		Protocol: access.ProtocolKey{Protocol: "vless", WireVersion: "0", FeatureProfile: "base"},
		Engine:   "native", Enabled: true,
		Listeners:        []access.Listener{{ID: newID(t), Transport: "tcp", Endpoint: access.Endpoint{Host: "192.0.2.1", Port: 443}}},
		DisplayEndpoints: []access.DisplayEndpoint{{ID: newID(t), Endpoint: access.Endpoint{Host: "example.test", Port: 443}}},
		Settings:         access.Settings{Schema: 1, Data: []byte(`{}`)},
		Stamp:            identity.NewStamp(time.Now()),
	}
	c := access.Credential{
		ID: newID(t), OwnerAccountID: &a.ID, Kind: access.UUID,
		Schema: 1, State: "active",
		Payload: access.UUIDPayload{UUID: secret.New("00000000-0000-4000-8000-000000000001")},
		Stamp:   identity.NewStamp(time.Now()),
	}
	b := access.Binding{ID: newID(t), AccountID: a.ID, InboundID: i.ID, CredentialID: c.ID, Enabled: true, Stamp: stamp}
	_, err = s.Transact(ctx, state.Revision, actor(t), func(w ports.Writer) error {
		if err := w.CreateAccount(a); err != nil {
			return err
		}
		if err := w.CreateInbound(i); err != nil {
			return err
		}
		if err := w.CreateCredential(c); err != nil {
			return err
		}
		return w.CreateBinding(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBindingEnabledClockRollbackPreservesCommittedStamp(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t)
	// A valid future committed stamp models a backward wall-clock adjustment
	// between creation and mutation without altering the process clock.
	stamp := identity.NewStamp(time.Now().Add(24 * time.Hour))
	stamp.UpdatedAt = stamp.CreatedAt.Add(time.Second)
	b := clockBinding(t, s, stamp)
	ids := map[identity.ID]bool{}
	for _, id := range []identity.ID{b.ID, b.AccountID, b.InboundID, b.CredentialID} {
		if ids[id] {
			t.Fatal("account, inbound, binding and credential identities overlap")
		}
		ids[id] = true
	}
	previous := b.UpdatedAt
	for n, enabled := range []bool{false, true} {
		resourceRevision := identity.Revision(n + 1)
		op, err := s.Transact(ctx, resourceRevision, actor(t), func(w ports.Writer) error {
			return w.(ports.BindingWriter).SetBindingEnabled(b.ID, enabled, resourceRevision)
		})
		if err != nil || op.State != identity.Committed {
			t.Fatal("binding toggle failed", err)
		}
		bindings, err := s.Bindings(ctx, b.InboundID)
		if err != nil || len(bindings) != 1 {
			t.Fatal("committed binding became unreadable", err)
		}
		got := bindings[0]
		if got.Validate() != nil || got.ID != b.ID || got.AccountID != b.AccountID || got.InboundID != b.InboundID || got.CredentialID != b.CredentialID || got.PolicyOverrideID != nil {
			t.Fatal("binding identities or linkage changed")
		}
		if got.Enabled != enabled || got.Revision != resourceRevision+1 || !got.CreatedAt.Equal(b.CreatedAt) || got.UpdatedAt.Before(previous) {
			t.Fatal("binding revision, enabled state or timestamp regressed")
		}
		previous = got.UpdatedAt
	}
	if _, err := s.Transact(ctx, 3, actor(t), func(w ports.Writer) error {
		return w.(ports.BindingWriter).SetBindingEnabled(b.ID, false, 1)
	}); !codeIs(err, identity.Conflict) {
		t.Fatal("stale binding revision accepted", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path, options(t))
	if err != nil {
		t.Fatal("reopen", err)
	}
	defer reopened.Close()
	got, err := reopened.Binding(ctx, b.InboundID)
	if err != nil || got.Validate() != nil || got.ID != b.ID || got.AccountID != b.AccountID || got.InboundID != b.InboundID || got.CredentialID != b.CredentialID || !got.Enabled || got.Revision != 3 || !got.CreatedAt.Equal(b.CreatedAt) || !got.UpdatedAt.Equal(previous) {
		t.Fatal("binding state was not durable or stale mutation changed it", err)
	}
	a, err := reopened.Account(ctx, b.AccountID)
	if err != nil || a.ID != b.AccountID {
		t.Fatal("account linkage lost", err)
	}
	c, err := reopened.RevealCredential(ctx, b.CredentialID)
	if err != nil || c.OwnerAccountID == nil || *c.OwnerAccountID != a.ID || c.ID != b.CredentialID || c.OwnerInboundID != nil || c.OwnerNodeID != nil {
		t.Fatal("credential ownership changed", err)
	}
	state, err := reopened.State(ctx)
	if err != nil || state.Revision != 3 || state.PendingTransactions != 0 {
		t.Fatal("committed revision or journal changed", err)
	}
}

func TestBindingEnabledClockRollbackRejectsCorruptStamp(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name             string
		created, updated string
	}{
		{name: "malformed-created", created: "invalid", updated: utc(now)},
		{name: "malformed-updated", created: utc(now), updated: "invalid"},
		{name: "inverted", created: utc(now), updated: utc(now.Add(-time.Second))},
		{name: "non-UTC", created: utc(now), updated: now.In(time.FixedZone("offset", 3600)).Format(time.RFC3339Nano)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, _ := newStore(t)
			b := clockBinding(t, s, identity.NewStamp(now))
			if _, err := s.db.ExecContext(ctx, "UPDATE bindings SET created_at=?,updated_at=? WHERE id=?", tc.created, tc.updated, b.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Bindings(ctx, b.InboundID); !codeIs(err, identity.Corrupt) {
				t.Fatal("corrupt fixture was not rejected by reader", err)
			}
			op, err := s.Transact(ctx, 1, actor(t), func(w ports.Writer) error {
				return w.(ports.BindingWriter).SetBindingEnabled(b.ID, false, 1)
			})
			if !codeIs(err, identity.Corrupt) || op.State != identity.Failed {
				t.Fatal("corrupt committed stamp was overwritten", err)
			}
			var enabled bool
			var revision identity.Revision
			var created, updated string
			if err := s.db.QueryRowContext(ctx, "SELECT enabled,revision,created_at,updated_at FROM bindings WHERE id=?", b.ID).Scan(&enabled, &revision, &created, &updated); err != nil {
				t.Fatal(err)
			}
			if !enabled || revision != 1 || created != tc.created || updated != tc.updated {
				t.Fatal("rejected mutation changed committed binding")
			}
			state, err := s.State(ctx)
			if err != nil || state.Revision != 1 || state.PendingTransactions != 0 {
				t.Fatal("rejected mutation partially committed or left pending journal", err)
			}
			if _, err := s.Bindings(ctx, b.InboundID); !codeIs(err, identity.Corrupt) {
				t.Fatal("corrupt state was suppressed", err)
			}
		})
	}
}
