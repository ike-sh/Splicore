package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/policy"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/secretvault"
)

func newID(t *testing.T) identity.ID {
	t.Helper()
	id, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestProcessFailureWALRecovery(t *testing.T) {
	if path := os.Getenv("SPLICORE_TEST_CRASH_DB"); path != "" {
		s, err := Open(context.Background(), path, options(t))
		if err != nil {
			t.Fatal(err)
		}
		a := account(t)
		_, _ = s.Transact(context.Background(), 0, actor(t), func(w ports.Writer) error {
			if err := w.CreateAccount(a); err != nil {
				t.Fatal(err)
			}
			os.Exit(77)
			return nil
		})
		t.Fatal("crash helper returned")
	}
	path := filepath.Join(t.TempDir(), "private", "state.db")
	command := exec.Command(os.Args[0], "-test.run=^TestProcessFailureWALRecovery$")
	command.Env = append(os.Environ(), "SPLICORE_TEST_CRASH_DB="+path)
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 77 {
		t.Fatal("crash injection did not execute", err)
	}
	s, err := Open(context.Background(), path, options(t))
	if err != nil {
		t.Fatal("WAL recovery failed", err)
	}
	defer s.Close()
	state, err := s.State(context.Background())
	if err != nil || state.Revision != 0 || state.PendingTransactions != 1 {
		t.Fatal("uncertain transaction concealed")
	}
	var count int
	if s.db.QueryRow("SELECT count(*) FROM accounts").Scan(&count) != nil || count != 0 {
		t.Fatal("uncommitted crash candidate admitted")
	}
	if _, err = s.Transact(context.Background(), 0, actor(t), func(w ports.Writer) error { return nil }); !codeIs(err, identity.Unavailable) {
		t.Fatal("mutation admitted before recovery review")
	}
}

func actor(t *testing.T) identity.Actor {
	return identity.Actor{Principal: "test-operator", RequestID: newID(t)}
}

func options(t *testing.T) Options {
	t.Helper()
	p, _, _, err := registry.Foundation()
	if err != nil {
		t.Fatal(err)
	}
	v, err := secretvault.New("fixture-key", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return Options{Cipher: v, CredentialKinds: func(k access.ProtocolKey) ([]access.CredentialKind, error) {
		entry, err := p.Get(k)
		if err != nil {
			return nil, err
		}
		return entry.Metadata().CredentialKinds, nil
	}}
}

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private", "state.db")
	s, err := Open(context.Background(), path, options(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func account(t *testing.T) access.Account {
	return access.Account{ID: newID(t), Name: "Alice", Status: access.Active, Enabled: true, Metadata: identity.Metadata{"notes": "fixture"}, Stamp: identity.NewStamp(time.Now())}
}

func codeIs(err error, code identity.Code) bool {
	var e *identity.Error
	return errors.As(err, &e) && e.Code == code
}

func TestFreshReopenExistingAndRevision(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "state.db")
	s, err := Open(ctx, path, options(t))
	if err != nil {
		t.Fatal(err)
	}
	initialState, err := s.State(ctx)
	if err != nil || initialState.Schema != 4 || initialState.Revision != 0 {
		t.Fatal("fresh state invalid")
	}
	if _, err = Open(ctx, path, options(t)); !codeIs(err, identity.Unavailable) {
		t.Fatal("second owner admitted")
	}
	a := account(t)
	expiry := time.Now().Add(time.Hour).UTC()
	a.ExpiresAt = &expiry
	op, err := s.Transact(ctx, 0, actor(t), func(w ports.Writer) error { return w.CreateAccount(a) })
	if err != nil || op.State != identity.Committed {
		t.Fatal(err)
	}
	a, err = s.Account(ctx, a.ID)
	if err != nil || a.ExpiresAt == nil || !a.ExpiresAt.Equal(expiry) {
		t.Fatal("account roundtrip", err)
	}
	a.Name = "Alice updated"
	if _, err = s.Transact(ctx, 1, actor(t), func(w ports.Writer) error { return w.UpdateAccount(a, 1) }); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Transact(ctx, 2, actor(t), func(w ports.Writer) error { return w.UpdateAccount(a, 1) }); !codeIs(err, identity.Conflict) {
		t.Fatal("stale resource revision accepted")
	}
	if _, err = s.Transact(ctx, 1, actor(t), func(w ports.Writer) error { return nil }); !codeIs(err, identity.Conflict) {
		t.Fatal("stale generation accepted")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path, options(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	state, err := s.State(ctx)
	if err != nil || state.NodeID != initialState.NodeID || state.Revision != 2 || state.PendingTransactions != 0 {
		t.Fatal("reopen identity/revision mismatch")
	}
	a, err = s.Account(ctx, a.ID)
	if err != nil || a.Name != "Alice updated" || a.Revision != 2 {
		t.Fatal("update not durable")
	}
	var count int
	if s.db.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&count) != nil || count != 4 {
		t.Fatal("migration repeated")
	}
}

func TestAtomicFailureAndConcurrentConflict(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	a := account(t)
	op, err := s.Transact(ctx, 0, actor(t), func(w ports.Writer) error {
		if err := w.CreateAccount(a); err != nil {
			return err
		}
		return errors.New("dummy-password")
	})
	if err == nil || strings.Contains(err.Error(), "dummy-password") || op.State != identity.Failed {
		t.Fatal("failure not safely journaled")
	}
	if _, err = s.Account(ctx, a.ID); !codeIs(err, identity.NotFound) {
		t.Fatal("failed candidate visible")
	}
	state, _ := s.State(ctx)
	if state.Revision != 0 {
		t.Fatal("failed revision published")
	}
	var committed, conflicts atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		a := account(t)
		act := actor(t)
		wg.Go(func() {
			_, err := s.Transact(ctx, 0, act, func(w ports.Writer) error { return w.CreateAccount(a) })
			if err == nil {
				committed.Add(1)
			} else if codeIs(err, identity.Conflict) {
				conflicts.Add(1)
			} else {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if committed.Load() != 1 || conflicts.Load() != 11 {
		t.Fatal("optimistic writer race", committed.Load(), conflicts.Load())
	}
}

func TestMigrationFailureRollsBack(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	steps := append(migrations(), migration{5, "0005_test_failure", "CREATE TABLE should_rollback(id INTEGER); INSERT INTO missing_table VALUES(1);"})
	if err = migrate(context.Background(), db, steps); !codeIs(err, identity.Corrupt) {
		t.Fatal("bad migration succeeded")
	}
	var count int
	if db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&count) != nil || count != 0 {
		t.Fatal("schema partially committed")
	}
	if err = migrate(context.Background(), db, migrations()); err != nil {
		t.Fatal("fresh migration retry", err)
	}
}

func TestFutureSchemaChecksumCorruptionAndMetadata(t *testing.T) {
	for _, mutation := range []string{"INSERT INTO schema_migrations VALUES(5,'future','future','future')", "UPDATE metadata SET value='wrong' WHERE key='product'", "UPDATE metadata SET value='wrong' WHERE key='db_schema'", "UPDATE schema_migrations SET checksum='wrong'", "UPDATE nodes SET id='wrong'", "DELETE FROM nodes"} {
		t.Run(mutation, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "private", "state.db")
			s, err := Open(ctx, path, options(t))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			s.Close()
			if s, err = Open(ctx, path, options(t)); err == nil {
				s.Close()
				t.Fatal("invalid state opened writable")
			}
			if !codeIs(err, identity.Corrupt) && !codeIs(err, identity.Unavailable) {
				t.Fatal("unclear invalid state error", err)
			}
		})
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "corrupt.db")
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(context.Background(), path, options(t)); err == nil {
		s.Close()
		t.Fatal("corrupt database replaced")
	}
}

func TestEveryPhysicalConnectionPragmasAndBusy(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	var connections []*sql.Conn
	for range 4 {
		c, err := s.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, c)
		for query, want := range map[string]int{"PRAGMA foreign_keys": 1, "PRAGMA synchronous": 2, "PRAGMA busy_timeout": 5000} {
			var got int
			if err = c.QueryRowContext(ctx, query).Scan(&got); err != nil || got != want {
				t.Fatal("connection pragma missing", query, got, err)
			}
		}
		var mode string
		if c.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" {
			t.Fatal("WAL absent")
		}
	}
	for _, c := range connections {
		c.Close()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	start := time.Now()
	other, err := s.db.BeginTx(ctx, nil)
	if err == nil {
		other.Rollback()
		t.Fatal("parallel writer admitted")
	}
	elapsed := time.Since(start)
	if elapsed < 4*time.Second || elapsed > 8*time.Second {
		t.Fatal("busy timeout unbounded", elapsed)
	}
}

func TestCredentialEncryptionOwnershipAndBinding(t *testing.T) {
	s, path := newStore(t)
	ctx := context.Background()
	state, _ := s.State(ctx)
	a := account(t)
	now := identity.NewStamp(time.Now())
	i := access.Inbound{ID: newID(t), NodeID: state.NodeID, Name: "VLESS fixture", Protocol: access.ProtocolKey{Protocol: "vless", WireVersion: "0", FeatureProfile: "base"}, Engine: "native", Listeners: []access.Listener{{ID: newID(t), Transport: "tcp", Endpoint: access.Endpoint{Host: "192.0.2.1", Port: 443}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: newID(t), Endpoint: access.Endpoint{Host: "example.com", Port: 443}}}, Settings: access.Settings{Schema: 1, Data: []byte(`{}`)}, Stamp: now}
	dummy := "00000000-0000-4000-8000-000000000001"
	c := access.Credential{ID: newID(t), OwnerAccountID: &a.ID, Kind: access.UUID, Schema: 1, State: "active", Payload: access.UUIDPayload{UUID: secret.New(dummy)}, Stamp: now}
	p := policy.TrafficPolicy{ID: newID(t), Stamp: now}
	b := access.Binding{ID: newID(t), AccountID: a.ID, InboundID: i.ID, CredentialID: c.ID, PolicyOverrideID: &p.ID, Stamp: now}
	_, err := s.Transact(ctx, 0, actor(t), func(w ports.Writer) error {
		if err := w.CreateAccount(a); err != nil {
			return err
		}
		if err := w.CreateInbound(i); err != nil {
			return err
		}
		if err := w.CreateCredential(c); err != nil {
			return err
		}
		if err := w.CreatePolicy(p); err != nil {
			return err
		}
		return w.CreateBinding(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	revealed, err := s.RevealCredential(ctx, c.ID)
	if err != nil || revealed.Payload.(access.UUIDPayload).UUID.Reveal() != dummy {
		t.Fatal("encrypted roundtrip", err)
	}
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(path + suffix)
		if err == nil && bytes.Contains(data, []byte(dummy)) {
			t.Fatal("plaintext persisted")
		}
	}
	other := account(t)
	b.ID = newID(t)
	b.AccountID = other.ID
	if _, err = s.Transact(ctx, 1, actor(t), func(w ports.Writer) error {
		if err := w.CreateAccount(other); err != nil {
			return err
		}
		return w.CreateBinding(b)
	}); !codeIs(err, identity.Invalid) {
		t.Fatal("cross-owner binding accepted")
	}
	if _, err = s.db.Exec("UPDATE credentials SET account_id=? WHERE id=?", newID(t), c.ID); err == nil {
		t.Fatal("foreign key not enforced")
	}
	if _, err = s.db.Exec("UPDATE credentials SET ciphertext=zeroblob(32) WHERE id=?", c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevealCredential(ctx, c.ID); !codeIs(err, identity.Corrupt) {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestMissingKeyAndCoherentSnapshot(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	a := account(t)
	_, err := s.Transact(ctx, 0, actor(t), func(w ports.Writer) error { return w.CreateAccount(a) })
	if err != nil {
		t.Fatal(err)
	}
	s.options.Cipher = nil
	c := access.Credential{ID: newID(t), OwnerAccountID: &a.ID, Kind: access.PSK, Schema: 1, State: "active", Payload: access.PSKPayload{Key: secret.New("dummy-psk")}, Stamp: identity.NewStamp(time.Now())}
	if _, err = s.Transact(ctx, 1, actor(t), func(w ports.Writer) error { return w.CreateCredential(c) }); !codeIs(err, identity.Unavailable) {
		t.Fatal("missing key writes plaintext")
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "snapshot.db")
	if _, err = s.db.Exec("VACUUM INTO ?", snapshot); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	backup, err := Open(ctx, snapshot, options(t))
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	state, err := backup.State(ctx)
	if err != nil || state.Revision != 1 {
		t.Fatal("snapshot lost committed WAL")
	}
	if _, err = backup.Account(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
}
