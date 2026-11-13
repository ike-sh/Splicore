package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

// Capture every stored column, including existing journal contents, not just
// row counts. Connection counters additionally catch writes undone afterwards.
type admissionSnapshot struct {
	Tables       map[string][]string
	TotalChanges int64
}

func admissionLogicalSnapshot(t *testing.T, s *Store) admissionSnapshot {
	t.Helper()
	ctx := context.Background()
	out := admissionSnapshot{Tables: map[string][]string{}}
	rows, err := s.db.QueryContext(ctx, "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	for _, name := range names {
		rows, err = s.db.QueryContext(ctx, `SELECT * FROM "`+strings.ReplaceAll(name, `"`, `""`)+`"`)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		out.Tables[name] = []string{}
		for rows.Next() {
			values, targets := make([]any, len(columns)), make([]any, len(columns))
			for i := range targets {
				targets[i] = &values[i]
			}
			if err = rows.Scan(targets...); err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			out.Tables[name] = append(out.Tables[name], string(b))
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		sort.Strings(out.Tables[name])
	}
	// Hold all four connections so each physical connection is counted once.
	var connections []*sql.Conn
	defer func() {
		for _, c := range connections {
			c.Close()
		}
	}()
	for range 4 {
		c, err := s.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, c)
		var changes int64
		if err = c.QueryRowContext(ctx, "SELECT total_changes()").Scan(&changes); err != nil {
			t.Fatal(err)
		}
		out.TotalChanges += changes
	}
	return out
}

func admissionFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(path + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		out["state.db"+suffix] = b
	}
	// LockFileEx excludes reads of the locked byte on Windows, including an
	// empty file read through a second handle. Keep the lock held and record
	// metadata instead; DB/WAL/SHM are still captured byte for byte.
	info, err := os.Lstat(path + ".lock")
	if err == nil {
		b, err := json.Marshal(map[string]any{"size": info.Size(), "mode": info.Mode().String(), "modified_at": info.ModTime()})
		if err != nil {
			t.Fatal(err)
		}
		out["installation-lock-metadata.json"] = b
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return out
}

func admissionEvidence(t *testing.T, label string, files map[string][]byte, state any) {
	t.Helper()
	root := os.Getenv("SPLICORE_STORAGE_SAFETY_EVIDENCE")
	if root == "" {
		return
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute external evidence path required")
	}
	dir := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "_"), label)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
		hashes[name] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	b, err := json.MarshalIndent(map[string]any{"state": state, "sha256": hashes}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "snapshot.json"), append(b, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func admissionUnchanged(t *testing.T, s *Store, path string, code identity.Code, call func() error) {
	t.Helper()
	before := admissionLogicalSnapshot(t, s)
	lockBefore, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	beforeFiles := admissionFiles(t, path)
	err = call()
	// Capture immediately, before the post-call read queries can touch SHM.
	afterFiles := admissionFiles(t, path)
	after := admissionLogicalSnapshot(t, s)
	admissionEvidence(t, "before-call", beforeFiles, before)
	admissionEvidence(t, "after-call", afterFiles, map[string]any{"snapshot": after, "error": fmt.Sprint(err)})
	if (code == "" && err != nil) || (code != "" && !codeIs(err, code)) {
		t.Errorf("expected stable rejection %s, got %v", code, err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("rejected call changed stored rows or SQLite total_changes: before=%+v after=%+v", before, after)
	}
	for _, name := range []string{"state.db", "state.db-wal", "installation-lock-metadata.json"} {
		if !reflect.DeepEqual(beforeFiles[name], afterFiles[name]) {
			t.Errorf("rejected call changed persistent file %s", name)
		}
	}
	lockAfter, statErr := os.Stat(path + ".lock")
	if statErr != nil || !os.SameFile(lockBefore, lockAfter) {
		t.Fatal("rejection replaced the installation lock", statErr)
	}
	// WAL-index/read marks are transient. Record any change explicitly; never
	// hide it behind a claim that all SQLite files remain byte-identical.
	var offsets []int
	a, b := beforeFiles["state.db-shm"], afterFiles["state.db-shm"]
	for i := range max(len(a), len(b)) {
		if i >= len(a) || i >= len(b) || a[i] != b[i] {
			offsets = append(offsets, i)
		}
	}
	t.Logf("rejection=%v db/wal byte equality=%t shm changed byte offsets=%v", err, reflect.DeepEqual(beforeFiles["state.db"], afterFiles["state.db"]) && reflect.DeepEqual(beforeFiles["state.db-wal"], afterFiles["state.db-wal"]), offsets)
}

func TestWriteAdmissionNoSideEffects(t *testing.T) {
	ctx := context.Background()
	for _, state := range []string{"pending-domain", "pending-runtime", "stale-revision", "invalid-metadata"} {
		for _, entry := range []string{"transact", "begin-runtime"} {
			t.Run(state+"/"+entry, func(t *testing.T) {
				s, path := newStore(t)
				admissionAccount(t, s, 0, "intact-baseline")
				expected, want := identity.Revision(1), identity.Unavailable
				switch state {
				case "pending-domain", "pending-runtime":
					op, err := s.BeginOperation(ctx, 1, actor(t))
					if err != nil {
						t.Fatal(err)
					}
					if state == "pending-domain" {
						if _, err = s.db.Exec("UPDATE transactions SET operation='domain' WHERE id=?", op.ID); err != nil {
							t.Fatal(err)
						}
					}
				case "stale-revision":
					expected, want = 0, identity.Conflict
				case "invalid-metadata":
					if _, err := s.db.Exec("UPDATE metadata SET value='invalid' WHERE key='db_schema'"); err != nil {
						t.Fatal(err)
					}
					want = identity.Corrupt
				}
				called := false
				admissionUnchanged(t, s, path, want, func() error {
					var err error
					if entry == "transact" {
						_, err = s.Transact(ctx, expected, actor(t), func(ports.Writer) error { called = true; return nil })
					} else {
						_, err = s.BeginRuntimeOperation(ctx, expected, actor(t), "runtime_replace")
					}
					return err
				})
				if called {
					t.Fatal("rejected command callback executed")
				}
			})
		}
	}
}

func TestAdmittedBusinessFailureStillAudited(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	a := account(t)
	op, err := s.Transact(ctx, 0, actor(t), func(w ports.Writer) error {
		if e := w.CreateAccount(a); e != nil {
			return e
		}
		return identity.Err(identity.Invalid, "synthetic validation failure")
	})
	if !codeIs(err, identity.Invalid) || op.State != identity.Failed {
		t.Fatal("normal business failure audit lost", op, err)
	}
	var state, code string
	var count int
	if err = s.db.QueryRow("SELECT state,failure_code FROM transactions WHERE id=?", op.ID).Scan(&state, &code); err != nil || state != "failed" || code != "invalid" {
		t.Fatal("failed journal missing", state, code, err)
	}
	if err = s.db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed candidate persisted", count, err)
	}
	admissionAccount(t, s, 0, "next-admitted-commit")
}

func TestRuntimeCompletionAdmissionNoSideEffects(t *testing.T) {
	ctx := context.Background()
	for _, state := range []string{"another-pending", "stale-revision", "invalid-metadata", "mismatched-operation"} {
		for _, entry := range []string{"commit", "fail"} {
			t.Run(state+"/"+entry, func(t *testing.T) {
				s, path := newStore(t)
				op, err := s.BeginRuntimeOperation(ctx, 0, actor(t), "runtime_replace")
				if err != nil {
					t.Fatal(err)
				}
				want := identity.Unavailable
				switch state {
				case "another-pending":
					if _, err = s.db.Exec(`INSERT INTO transactions SELECT ?,state,base_revision,target_revision,principal,request_id,created_at,updated_at,failure_code,operation FROM transactions WHERE id=?`, newID(t), op.ID); err != nil {
						t.Fatal(err)
					}
				case "stale-revision":
					if _, err = s.db.Exec("UPDATE settings SET committed_revision=1"); err != nil {
						t.Fatal(err)
					}
					want = identity.Conflict
				case "invalid-metadata":
					if _, err = s.db.Exec("UPDATE metadata SET value='invalid' WHERE key='db_schema'"); err != nil {
						t.Fatal(err)
					}
					want = identity.Corrupt
				case "mismatched-operation":
					op.TargetRevision++
					want = identity.Invalid
				}
				called := false
				admissionUnchanged(t, s, path, want, func() error {
					if entry == "fail" {
						return s.FailOperation(ctx, op)
					}
					return s.CommitOperation(ctx, op, func(ports.Writer) error { called = true; return nil })
				})
				if called {
					t.Fatal("rejected runtime callback executed")
				}
			})
		}
	}
}

func TestRuntimeCompletionAndFailureAudit(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	op, err := s.BeginOperation(ctx, 0, actor(t))
	if err != nil {
		t.Fatal(err)
	}
	a := account(t)
	if err = s.CommitOperation(ctx, op, func(w ports.Writer) error { return w.CreateAccount(a) }); err != nil {
		t.Fatal(err)
	}
	op, err = s.BeginOperation(ctx, 1, actor(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitOperation(ctx, op, func(ports.Writer) error { return identity.Err(identity.Invalid, "synthetic business failure") }); !codeIs(err, identity.Invalid) {
		t.Fatal(err)
	}
	if err = s.FailOperation(ctx, op); err != nil {
		t.Fatal("owned failure could not be audited", err)
	}
	state, err := s.State(ctx)
	if err != nil || state.Revision != 1 || state.PendingTransactions != 0 {
		t.Fatal(state, err)
	}
	var failed int
	if err = s.db.QueryRow("SELECT count(*) FROM transactions WHERE state='failed' AND failure_code='unavailable'").Scan(&failed); err != nil || failed != 1 {
		t.Fatal("runtime failure audit missing", failed, err)
	}
}

func TestPendingMigrationAdmissionNoSideEffects(t *testing.T) {
	s, path := newStore(t)
	ctx := context.Background()
	if _, err := s.BeginOperation(ctx, 0, actor(t)); err != nil {
		t.Fatal(err)
	}
	steps := append(migrations(), migration{9, "qualification_only", "CREATE TABLE must_not_exist(id INTEGER)"})
	admissionUnchanged(t, s, path, identity.Unavailable, func() error {
		return migrate(ctx, s.db, steps)
	})
}

func admissionAccount(t *testing.T, s *Store, rev identity.Revision, name string) access.Account {
	t.Helper()
	a := account(t)
	a.Name = name
	if _, err := s.Transact(context.Background(), rev, actor(t), func(w ports.Writer) error { return w.CreateAccount(a) }); err != nil {
		t.Fatal(err)
	}
	return a
}
