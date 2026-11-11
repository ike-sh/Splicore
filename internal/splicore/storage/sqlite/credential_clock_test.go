package sqlite

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func credentialClockFixture(t *testing.T, s *Store, binding, credential identity.Stamp) (access.Binding, access.Credential) {
	t.Helper()
	ctx := context.Background()
	b := clockBinding(t, s, binding)
	// A valid committed future Stamp models the state observed after the wall
	// clock moves backwards. Neither the host clock nor a global fixture changes.
	if _, err := s.db.ExecContext(ctx, "UPDATE credentials SET created_at=?,updated_at=? WHERE id=?", utc(credential.CreatedAt), utc(credential.UpdatedAt), b.CredentialID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Binding(ctx, b.InboundID)
	if err != nil || got.Validate() != nil {
		t.Fatal("invalid initial binding", err)
	}
	c, err := s.RevealCredential(ctx, b.CredentialID)
	if err != nil || c.Validate() != nil {
		t.Fatal("invalid initial credential", err)
	}
	return got, c
}

type credentialClockRows struct {
	bindingEnabled                  bool
	bindingRevision, secretRevision identity.Revision
	bindingCreated, bindingUpdated  string
	secretCreated, secretUpdated    string
	ciphertext                      string
}

func readCredentialClockRows(t *testing.T, s *Store, b access.Binding) credentialClockRows {
	t.Helper()
	var out credentialClockRows
	if err := s.db.QueryRow("SELECT enabled,revision,created_at,updated_at FROM bindings WHERE id=?", b.ID).Scan(&out.bindingEnabled, &out.bindingRevision, &out.bindingCreated, &out.bindingUpdated); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT revision,created_at,updated_at,hex(ciphertext) FROM credentials WHERE id=?", b.CredentialID).Scan(&out.secretRevision, &out.secretCreated, &out.secretUpdated, &out.ciphertext); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCredentialRotationClockRollbackPreservesCommittedStamps(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name                          string
		bindingUpdated, secretUpdated time.Duration
	}{
		{name: "equal"},
		{name: "binding-later", bindingUpdated: 10 * time.Second, secretUpdated: 3 * time.Second},
		{name: "credential-later", bindingUpdated: 3 * time.Second, secretUpdated: 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := newStore(t)
			now := time.Now().UTC().Add(7 * 24 * time.Hour)
			t0 := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), 999999999, time.UTC)
			bindingStamp := identity.NewStamp(t0)
			bindingStamp.UpdatedAt = t0.Add(tc.bindingUpdated)
			secretStamp := identity.NewStamp(t0.Add(-time.Nanosecond))
			secretStamp.UpdatedAt = t0.Add(tc.secretUpdated)
			b, c := credentialClockFixture(t, s, bindingStamp, secretStamp)
			originalBinding, originalSecret := b, c
			ids := map[identity.ID]bool{}
			for _, id := range []identity.ID{b.ID, b.AccountID, b.InboundID, c.ID} {
				if ids[id] {
					t.Fatal("account, inbound, binding and credential identities overlap")
				}
				ids[id] = true
			}
			wantTime := bindingStamp.UpdatedAt
			if secretStamp.UpdatedAt.After(wantTime) {
				wantTime = secretStamp.UpdatedAt
			}
			var lastPayload string
			for n := range 3 {
				before := readCredentialClockRows(t, s, b)
				lastPayload = fmt.Sprintf("00000000-0000-4000-8000-%012d", n+2)
				c.Payload = access.UUIDPayload{UUID: secret.New(lastPayload)}
				state, err := s.State(ctx)
				if err != nil {
					t.Fatal(err)
				}
				op, err := s.Transact(ctx, state.Revision, actor(t), func(w ports.Writer) error {
					return w.(ports.UserWriter).RotateBindingCredential(b, c, b.Revision)
				})
				if err != nil || op.State != identity.Committed {
					t.Fatal("rotation failed", err, op.State)
				}
				b, err = s.Binding(ctx, b.InboundID)
				if err != nil || b.Validate() != nil {
					t.Fatal("committed binding is invalid", err)
				}
				c, err = s.RevealCredential(ctx, c.ID)
				if err != nil || c.Validate() != nil {
					t.Fatal("committed credential is invalid", err)
				}
				if b.ID != originalBinding.ID || b.AccountID != originalBinding.AccountID || b.InboundID != originalBinding.InboundID || b.CredentialID != originalBinding.CredentialID || b.PolicyOverrideID != nil || !b.Enabled || !b.CreatedAt.Equal(originalBinding.CreatedAt) || b.Revision != identity.Revision(n+2) {
					t.Fatal("rotation changed binding identity, creation time or revision")
				}
				if c.ID != originalSecret.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != originalBinding.AccountID || c.OwnerInboundID != nil || c.OwnerNodeID != nil || c.Kind != originalSecret.Kind || c.Schema != originalSecret.Schema || c.State != originalSecret.State || !c.CreatedAt.Equal(originalSecret.CreatedAt) || c.Revision != identity.Revision(n+2) || c.Payload.(access.UUIDPayload).UUID.Reveal() != lastPayload {
					t.Fatal("rotation changed credential identity, ownership, creation time or payload semantics")
				}
				after := readCredentialClockRows(t, s, b)
				if !b.UpdatedAt.Equal(wantTime) || !c.UpdatedAt.Equal(wantTime) || after.bindingCreated != before.bindingCreated || after.secretCreated != before.secretCreated || after.bindingUpdated != utc(wantTime) || after.secretUpdated != utc(wantTime) || after.ciphertext == before.ciphertext {
					t.Fatal("rotation did not preserve exact committed timestamp floors or change ciphertext")
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(ctx, path, options(t))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			gotBinding, err := reopened.Binding(ctx, b.InboundID)
			if err != nil || gotBinding.Validate() != nil || gotBinding.ID != b.ID || gotBinding.Revision != 4 || !gotBinding.CreatedAt.Equal(originalBinding.CreatedAt) || !gotBinding.UpdatedAt.Equal(wantTime) {
				t.Fatal("binding not durable", err)
			}
			gotSecret, err := reopened.RevealCredential(ctx, c.ID)
			if err != nil || gotSecret.Validate() != nil || gotSecret.ID != c.ID || gotSecret.OwnerAccountID == nil || *gotSecret.OwnerAccountID != b.AccountID || gotSecret.Revision != 4 || !gotSecret.CreatedAt.Equal(originalSecret.CreatedAt) || !gotSecret.UpdatedAt.Equal(wantTime) || gotSecret.Payload.(access.UUIDPayload).UUID.Reveal() != lastPayload {
				t.Fatal("credential not durable", err)
			}
			state, err := reopened.State(ctx)
			if err != nil || state.Revision != 4 || state.PendingTransactions != 0 {
				t.Fatal("rotation generation or journal not durable", err)
			}
		})
	}
}

func TestCredentialRotationRejectsCorruptCommittedStamp(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Add(24 * time.Hour)
	for _, table := range []string{"credentials", "bindings"} {
		for _, tc := range []struct {
			name, created, updated string
		}{
			{name: "malformed-created", created: "invalid", updated: utc(now)},
			{name: "malformed-updated", created: utc(now), updated: "invalid"},
			{name: "inverted", created: utc(now), updated: utc(now.Add(-time.Nanosecond))},
			{name: "non-UTC", created: utc(now), updated: now.In(time.FixedZone("offset", 3600)).Format(time.RFC3339Nano)},
			{name: "zero-created", created: utc(time.Time{}), updated: utc(now)},
		} {
			t.Run(table+"/"+tc.name, func(t *testing.T) {
				s, _ := newStore(t)
				b, c := credentialClockFixture(t, s, identity.NewStamp(now), identity.NewStamp(now))
				c.Payload = access.UUIDPayload{UUID: secret.New("00000000-0000-4000-8000-000000000002")}
				id := b.ID
				query := "UPDATE bindings SET created_at=?,updated_at=? WHERE id=?"
				if table == "credentials" {
					id = c.ID
					query = "UPDATE credentials SET created_at=?,updated_at=? WHERE id=?"
				}
				if _, err := s.db.ExecContext(ctx, query, tc.created, tc.updated, id); err != nil {
					t.Fatal(err)
				}
				before := readCredentialClockRows(t, s, b)
				op, err := s.Transact(ctx, 1, actor(t), func(w ports.Writer) error {
					return w.(ports.UserWriter).RotateBindingCredential(b, c, 1)
				})
				if !codeIs(err, identity.Corrupt) || op.State != identity.Failed {
					t.Fatal("corrupt committed Stamp was accepted", err, op.State)
				}
				if readCredentialClockRows(t, s, b) != before {
					t.Fatal("failed rotation partially mutated or silently repaired committed state")
				}
				if table == "credentials" {
					if _, err := s.RevealCredential(ctx, c.ID); !codeIs(err, identity.Corrupt) {
						t.Fatal("corrupt credential reader was weakened", err)
					}
				} else if _, err := s.Bindings(ctx, b.InboundID); !codeIs(err, identity.Corrupt) {
					t.Fatal("corrupt binding reader was weakened", err)
				}
				state, err := s.State(ctx)
				if err != nil || state.Revision != 1 || state.PendingTransactions != 0 {
					t.Fatal("failed rotation changed generation or left pending journal", err)
				}
			})
		}
	}
}

func TestCredentialRotationSQLFailureRollsBackRelatedRows(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t)
	stamp := identity.NewStamp(time.Now().Add(24 * time.Hour))
	b, c := credentialClockFixture(t, s, stamp, stamp)
	c.Payload = access.UUIDPayload{UUID: secret.New("00000000-0000-4000-8000-000000000002")}
	before := readCredentialClockRows(t, s, b)
	if _, err := s.db.ExecContext(ctx, "CREATE TRIGGER reject_clock_binding_update BEFORE UPDATE ON bindings BEGIN SELECT RAISE(ABORT, 'clock fixture binding failure'); END"); err != nil {
		t.Fatal(err)
	}
	op, err := s.Transact(ctx, 1, actor(t), func(w ports.Writer) error {
		return w.(ports.UserWriter).RotateBindingCredential(b, c, 1)
	})
	if err == nil || op.State != identity.Failed {
		t.Fatal("SQL failure did not reject the operation", err, op.State)
	}
	if readCredentialClockRows(t, s, b) != before {
		t.Fatal("SQL failure partially committed binding, credential or ciphertext")
	}
	state, err := s.State(ctx)
	if err != nil || state.Revision != 1 || state.PendingTransactions != 0 {
		t.Fatal("SQL failure changed generation or left pending journal", err)
	}
	if _, err := s.RevealCredential(ctx, c.ID); err != nil {
		t.Fatal("original credential lost after SQL rollback", err)
	}
	if _, err := s.Binding(ctx, b.InboundID); err != nil {
		t.Fatal("original binding lost after SQL rollback", err)
	}
}
