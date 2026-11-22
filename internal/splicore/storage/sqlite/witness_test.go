package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

const witnessCrashPath = "SPLICORE_TEST_WITNESS_CRASH_DB"

func TestCommitWitnessFailClosed(t *testing.T) {
	ctx := context.Background()
	if path := os.Getenv(witnessCrashPath); path != "" {
		s, err := Open(ctx, path, options(t))
		if err != nil {
			t.Fatal(err)
		}
		s.afterDatabaseCommit = func() { os.Exit(78) }
		a := account(t)
		a.Name = "committed-before-witness-crash"
		_, _ = s.Transact(ctx, 0, actor(t), func(w ports.Writer) error { return w.CreateAccount(a) })
		t.Fatal("post-commit crash hook returned")
	}

	t.Run("db-commit-before-witness-crash", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private", "state.db")
		s, err := Open(ctx, path, options(t))
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(os.Args[0], "-test.run=^TestCommitWitnessFailClosed$")
		command.Env = append(os.Environ(), witnessCrashPath+"="+path)
		err = command.Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 78 {
			t.Fatal("commit/witness crash window not reached", err)
		}
		w, err := readWitness(path + witnessSuffix)
		if err != nil || w.Revision != 0 {
			t.Fatal("older durable witness was not preserved", w.Revision, err)
		}
		u, _ := readOnlyDatabaseURL(path)
		db, err := sql.Open("sqlite", u)
		if err != nil {
			t.Fatal(err)
		}
		var revision, accounts int
		if err = db.QueryRow(`SELECT (SELECT committed_revision FROM settings WHERE singleton=1),(SELECT count(*) FROM accounts)`).Scan(&revision, &accounts); err != nil {
			db.Close()
			t.Fatal(err)
		}
		db.Close()
		if revision != 1 || accounts != 1 {
			t.Fatal("database commit did not precede crash", revision, accounts)
		}
		if reopened, openErr := Open(ctx, path, options(t)); reopened != nil || !codeIs(openErr, identity.StorageIntegrityUnverified) {
			if reopened != nil {
				reopened.Close()
			}
			t.Fatal("unwitnessed committed generation reopened", openErr)
		}
	})

	for _, mode := range []string{"permission", "no-space", "partial-write"} {
		t.Run("witness-io-failure-"+mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private", "state.db")
			var sealed atomic.Int32
			opts := options(t)
			opts.OnIntegrityFailure = func() { sealed.Add(1) }
			s, err := Open(ctx, path, opts)
			if err != nil {
				t.Fatal(err)
			}
			s.persistWitness = func(databasePath string, _ *commitWitness, _ commitWitness) error {
				switch mode {
				case "permission":
					return os.ErrPermission
				case "no-space":
					return syscall.ENOSPC
				default:
					if writeErr := os.WriteFile(databasePath+pendingSuffix, []byte(`{"partial":`), 0o600); writeErr != nil {
						return writeErr
					}
					return errors.New("synthetic partial durable write")
				}
			}
			firstCalled := false
			op, err := s.Transact(ctx, 0, actor(t), func(w ports.Writer) error {
				firstCalled = true
				return w.CreateAccount(account(t))
			})
			if !firstCalled || !codeIs(err, identity.StorageIntegrityUnverified) || op.State != identity.Pending || sealed.Load() != 1 {
				t.Fatal("witness failure was not distinctly sealed", firstCalled, op.State, sealed.Load(), err)
			}
			secondCalled := false
			if _, err = s.Transact(ctx, 1, actor(t), func(ports.Writer) error { secondCalled = true; return nil }); !codeIs(err, identity.StorageIntegrityUnverified) || secondCalled || sealed.Load() != 1 {
				t.Fatal("latched integrity failure admitted retry", secondCalled, sealed.Load(), err)
			}
			var revision int
			if err = s.db.QueryRow("SELECT committed_revision FROM settings WHERE singleton=1").Scan(&revision); err != nil || revision != 1 {
				t.Fatal("fault did not exercise post-commit boundary", revision, err)
			}
			s.Close()
			if reopened, openErr := Open(ctx, path, options(t)); reopened != nil || !codeIs(openErr, identity.StorageIntegrityUnverified) {
				if reopened != nil {
					reopened.Close()
				}
				t.Fatal("database ahead of witness reopened", openErr)
			}
		})
	}

	for _, fault := range []string{"missing", "corrupt", "rollback", "ahead", "same-revision-content", "transaction-row", "partial-pending"} {
		t.Run(fault, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private", "state.db")
			s, err := Open(ctx, path, options(t))
			if err != nil {
				t.Fatal(err)
			}
			initialBytes, err := os.ReadFile(path + witnessSuffix)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Transact(ctx, 0, actor(t), func(w ports.Writer) error { return w.CreateAccount(account(t)) }); err != nil {
				t.Fatal(err)
			}
			current := s.witness
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "missing":
				if err = os.Remove(path + witnessSuffix); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				data, readErr := os.ReadFile(path + witnessSuffix)
				if readErr != nil {
					t.Fatal(readErr)
				}
				data[len(data)/2] ^= 1
				if err = os.WriteFile(path+witnessSuffix, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "rollback":
				if err = os.WriteFile(path+witnessSuffix, initialBytes, 0o600); err != nil {
					t.Fatal(err)
				}
			case "ahead":
				id, idErr := identity.NewID()
				if idErr != nil {
					t.Fatal(idErr)
				}
				ahead := nextWitness(current, identity.Transaction{ID: id, TargetRevision: current.Revision + 1}, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
				data, encodeErr := encodeWitness(ahead)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				if err = os.WriteFile(path+witnessSuffix, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "same-revision-content":
				u, _ := writableExistingDatabaseURL(path)
				db, openErr := sql.Open("sqlite", u)
				if openErr != nil {
					t.Fatal(openErr)
				}
				if _, err = db.Exec("UPDATE accounts SET name='unwitnessed-change'"); err != nil {
					db.Close()
					t.Fatal(err)
				}
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
			case "transaction-row":
				u, _ := writableExistingDatabaseURL(path)
				db, openErr := sql.Open("sqlite", u)
				if openErr != nil {
					t.Fatal(openErr)
				}
				if _, err = db.Exec("DELETE FROM transactions WHERE id=?", current.TransactionID); err != nil {
					db.Close()
					t.Fatal(err)
				}
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
			case "partial-pending":
				if err = os.WriteFile(path+pendingSuffix, []byte(`{"format":`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, openErr := Open(ctx, path, options(t)); reopened != nil || !codeIs(openErr, identity.StorageIntegrityUnverified) {
				if reopened != nil {
					reopened.Close()
				}
				t.Fatal("witness fault opened writable", openErr)
			}
			inspection, inspectErr := InspectCommitWitness(ctx, path)
			if inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if inspection.Status == "verified" {
				t.Fatal("witness fault reported verified", inspection)
			}
		})
	}
}

func TestCommitWitnessLegacyLifecycle(t *testing.T) {
	ctx := context.Background()
	t.Run("canceled-admission-does-not-poison", func(t *testing.T) {
		cancelPath := filepath.Join(t.TempDir(), "private", "state.db")
		store, openErr := Open(ctx, cancelPath, options(t))
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer store.Close()
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		called := false
		if _, mutationErr := store.Transact(canceled, 0, actor(t), func(ports.Writer) error { called = true; return nil }); mutationErr == nil || called || store.integrityFailure() != nil {
			t.Fatal("ordinary cancellation poisoned witnessed state", called, mutationErr, store.integrityFailure())
		}
		if _, mutationErr := store.Transact(ctx, 0, actor(t), func(ports.Writer) error { return nil }); mutationErr != nil {
			t.Fatal("valid mutation rejected after cancellation", mutationErr)
		}
	})
	path := filepath.Join(t.TempDir(), "private", "state.db")
	s, err := Open(ctx, path, options(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Transact(ctx, 0, actor(t), func(w ports.Writer) error { return w.CreateAccount(account(t)) }); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path + witnessSuffix); err != nil {
		t.Fatal(err)
	}
	if reopened, openErr := Open(ctx, path, options(t)); reopened != nil || !codeIs(openErr, identity.StorageIntegrityUnverified) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatal("legacy state opened without explicit baseline", openErr)
	}
	if _, err = EstablishCommitWitness(ctx, path, false); !codeIs(err, identity.Invalid) {
		t.Fatal("implicit legacy acknowledgement accepted", err)
	}
	inspection, err := EstablishCommitWitness(ctx, path, true)
	if err != nil || inspection.Status != "verified" || inspection.Lineage != witnessLineageLegacy || inspection.HistoricalProof {
		t.Fatal("legacy boundary not retained", inspection, err)
	}
	s, err = Open(ctx, path, options(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Transact(ctx, 1, actor(t), func(w ports.Writer) error { return w.CreateAccount(account(t)) }); err != nil {
		t.Fatal(err)
	}
	if s.witness.Lineage != witnessLineageLegacy || s.witness.Revision != 2 {
		t.Fatal("legacy provenance disappeared after commit", s.witness)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	inspection, err = InspectCommitWitness(ctx, path)
	if err != nil || inspection.Status != "verified" || inspection.WitnessRevision != 2 || inspection.HistoricalProof {
		t.Fatal("legacy witnessed restart invalid", inspection, err)
	}
	if _, err = EstablishCommitWitness(ctx, path, true); !codeIs(err, identity.Invalid) {
		t.Fatal("existing witness was overwritten", err)
	}
}
