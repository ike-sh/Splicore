package sqlite

// Synthetic disk-backed reliability campaign. Production SQLite/Vault semantics
// and PRAGMA settings remain unchanged. Process failure is not power loss.
import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/secretvault"
)

// TestPersistenceReliability owns every synthetic DB and subprocess. Optional
// evidence retention must point outside the source tree. CI artifacts retain
// each original/recovered DB/WAL/SHM and per-cut outcome without key bytes.
func TestPersistenceReliability(t *testing.T) {
	if os.Getenv("P3_WORKER_ROOT") != "" {
		p3CrashWorker(t)
		return
	}
	root := t.TempDir()
	evidence := filepath.Join(root, "evidence")
	if parent := os.Getenv("SPLICORE_PERSISTENCE_EVIDENCE"); parent != "" {
		if !filepath.IsAbs(parent) {
			t.Fatal("absolute external evidence path required")
		}
		if e := os.MkdirAll(parent, 0700); e != nil {
			t.Fatal(e)
		}
		var e error
		evidence, e = os.MkdirTemp(parent, "reliability-")
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := os.MkdirAll(evidence, 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("P3_ROOT", root)
	t.Setenv("P3_EVIDENCE", evidence)
	t.Log("process crash, not OS/power loss; artifacts:", evidence)
	t.Run("parameters-and-reopen", p3Parameters)
	t.Run("concurrent-readers-during-write", p3ConcurrentReadWrite)
	t.Run("process-crash-recovery", p3CrashRecovery)
	t.Run("backup-vault-pair", p3BackupVaultPair)
	t.Run("native-wal-observation", p3IndependentWALTail)
	t.Run("committed-wal-safety-boundary", p31WALSafetyBoundary)
}

// Readers use separate physical SQLite connections while a real transaction
// holds an uncommitted row. WAL must expose the complete committed generation,
// then publish the new row and revision together after Commit.
func p3ConcurrentReadWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s := p3open(t, filepath.Join(p3root(t, "concurrent"), "state.db"))
	defer s.Close()
	p3account(t, s, 0, "committed-before-concurrency")
	candidate, who := account(t), actor(t)
	candidate.Name = "candidate-visible-only-after-commit"
	staged, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := s.Transact(ctx, 1, who, func(w ports.Writer) error {
			if err := w.CreateAccount(candidate); err != nil {
				return err
			}
			close(staged)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		done <- err
	}()
	select {
	case <-staged:
	case err := <-done:
		t.Fatal("writer never staged", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var workers sync.WaitGroup
	errorsFound := make(chan error, 8)
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 64 {
				var revision, count int
				if err := s.db.QueryRowContext(ctx, `SELECT (SELECT committed_revision FROM settings WHERE singleton=1), (SELECT count(*) FROM accounts)`).Scan(&revision, &count); err != nil {
					errorsFound <- err
					return
				}
				if revision != 1 || count != 1 {
					errorsFound <- fmt.Errorf("uncommitted generation visible revision=%d accounts=%d", revision, count)
					return
				}
				if _, err := s.Account(ctx, candidate.ID); !codeIs(err, identity.NotFound) {
					errorsFound <- fmt.Errorf("uncommitted application row visible: %v", err)
					return
				}
			}
		}()
	}
	workers.Wait()
	close(errorsFound)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for err := range errorsFound {
		t.Error(err)
	}
	p3integrity(t, s, 2)
	state, err := s.State(ctx)
	if err != nil || state.Revision != 2 || state.PendingTransactions != 0 {
		t.Fatal("commit publication", state, err)
	}
	if got, err := s.Account(ctx, candidate.ID); err != nil || got.Name != candidate.Name {
		t.Fatal("committed candidate unavailable", err)
	}
	p3json(t, "concurrent-read-write", map[string]any{"readers": 8, "snapshot_checks": 512, "uncommitted_rows_visible": 0, "after_commit_revision": state.Revision, "after_commit_accounts": 2})
}

func p3root(t *testing.T, name string) string {
	t.Helper()
	root := os.Getenv("P3_ROOT")
	if root == "" {
		t.Fatal("P3_ROOT must name the disposable disk-backed test root")
	}
	p := filepath.Join(root, name)
	if e := privateDirectory(p); e != nil {
		t.Fatal(e)
	}
	return p
}
func p3json(t *testing.T, name string, value any) {
	t.Helper()
	p := filepath.Join(os.Getenv("P3_EVIDENCE"), name+".json")
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, append(b, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}
func p3open(t *testing.T, path string) *Store {
	t.Helper()
	s, e := Open(context.Background(), path, options(t))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func p3account(t *testing.T, s *Store, rev identity.Revision, name string) access.Account {
	t.Helper()
	a := account(t)
	a.Name = name
	if _, e := s.Transact(context.Background(), rev, actor(t), func(w ports.Writer) error { return w.CreateAccount(a) }); e != nil {
		t.Fatal(e)
	}
	return a
}
func p3integrity(t *testing.T, s *Store, want int) {
	t.Helper()
	var integrity string
	if e := s.db.QueryRow("PRAGMA integrity_check").Scan(&integrity); e != nil || integrity != "ok" {
		t.Fatal("integrity_check", integrity, e)
	}
	rows, e := s.db.Query("PRAGMA foreign_key_check")
	if e != nil {
		t.Fatal(e)
	}
	if rows.Next() {
		rows.Close()
		t.Fatal("foreign key violation")
	}
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
	rows.Close()
	var count int
	if e = s.db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); e != nil || count != want {
		t.Fatal("application account count", count, want, e)
	}
}

func p3Parameters(t *testing.T) {
	path := filepath.Join(p3root(t, "parameters"), "state.db")
	s := p3open(t, path)
	defer s.Close()
	values := map[string]any{"go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "encryption": "AES-256-GCM credential/source fields; database metadata is not whole-file encrypted", "transaction_lock": "immediate", "max_open_connections": s.db.Stats().MaxOpenConnections}
	for _, q := range []string{"SELECT sqlite_version()", "SELECT sqlite_source_id()", "PRAGMA journal_mode", "PRAGMA synchronous", "PRAGMA busy_timeout", "PRAGMA foreign_keys", "PRAGMA wal_autocheckpoint", "PRAGMA page_size", "PRAGMA locking_mode", "PRAGMA cache_size", "PRAGMA journal_size_limit", "PRAGMA mmap_size", "PRAGMA user_version", "SELECT value FROM metadata WHERE key='db_schema'"} {
		var v any
		if e := s.db.QueryRow(q).Scan(&v); e != nil {
			t.Fatal(q, e)
		}
		values[q] = v
	}
	p3account(t, s, 0, "committed-baseline")
	p3integrity(t, s, 1)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	for range 3 {
		s = p3open(t, path)
		var n int
		if e := s.db.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&n); e != nil || n != 8 {
			t.Fatal("migration not idempotent", n, e)
		}
		p3integrity(t, s, 1)
		s.Close()
	}
	p3json(t, "parameters", values)
}

func p3CrashWorker(t *testing.T) {
	root := os.Getenv("P3_WORKER_ROOT")
	if root == "" {
		return
	}
	phase := os.Getenv("P3_PHASE")
	mode := os.Getenv("P3_MODE")
	s := p3open(t, filepath.Join(root, "state.db"))
	signal := func() {
		fmt.Println("P3_READY " + phase)
		if mode == "exit" {
			os.Exit(77)
		}
		select {}
	}
	if phase == "begin" || phase == "write" || phase == "pre-commit" {
		_, e := s.Transact(context.Background(), 1, actor(t), func(w ports.Writer) error {
			if phase == "begin" {
				signal()
			}
			for i := 0; i < 2; i++ {
				a := account(t)
				a.Name = fmt.Sprintf("candidate-%d", i)
				if e := w.CreateAccount(a); e != nil {
					return e
				}
				if phase == "write" && i == 0 {
					signal()
				}
			}
			signal()
			return nil
		})
		t.Fatal("crash point returned", e)
	}
	if phase == "after-runtime-commit" {
		op, err := s.BeginRuntimeOperation(context.Background(), 1, actor(t), "runtime_replace")
		if err != nil {
			t.Fatal(err)
		}
		a := account(t)
		a.Name = "acknowledged-after-commit"
		if err = s.CommitOperation(context.Background(), op, func(w ports.Writer) error { return w.CreateAccount(a) }); err != nil {
			t.Fatal(err)
		}
	} else {
		p3account(t, s, 1, "acknowledged-after-commit")
	}
	if phase == "checkpoint-complete" {
		var busy, log, done int
		if e := s.db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); e != nil || busy != 0 {
			t.Fatal("checkpoint", busy, log, done, e)
		}
	}
	if phase == "normal-close" {
		if e := s.Close(); e != nil {
			t.Fatal(e)
		}
		fmt.Println("P3_READY " + phase)
		return
	}
	signal()
}

// This is a diagnostic capture of a dead child's DB/WAL/SHM, not a backup.
func p3capture(t *testing.T, root, name string) {
	t.Helper()
	dst := filepath.Join(os.Getenv("P3_EVIDENCE"), name)
	if e := os.MkdirAll(dst, 0700); e != nil {
		t.Fatal(e)
	}
	for _, suffix := range []string{"", "-wal", "-shm", ".lock"} {
		b, e := os.ReadFile(filepath.Join(root, "state.db") + suffix)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dst, "state.db")+suffix, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func p3CrashRecovery(t *testing.T) {
	for _, phase := range []string{"begin", "write", "pre-commit", "after-commit", "after-runtime-commit", "checkpoint-complete", "normal-close"} {
		for _, mode := range []string{"exit", "kill"} {
			if phase == "normal-close" && mode == "kill" {
				continue
			}
			t.Run(phase+"-"+mode, func(t *testing.T) {
				name := phase + "-" + mode
				root := p3root(t, name)
				path := filepath.Join(root, "state.db")
				s := p3open(t, path)
				baseline := p3account(t, s, 0, "committed-baseline")
				if e := s.Close(); e != nil {
					t.Fatal(e)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPersistenceReliability$", "-test.v")
				cmd.Env = append(os.Environ(), "P3_WORKER_ROOT="+root, "P3_PHASE="+phase, "P3_MODE="+mode)
				out, e := cmd.StdoutPipe()
				if e != nil {
					t.Fatal(e)
				}
				log, e := os.Create(filepath.Join(os.Getenv("P3_EVIDENCE"), name+"-child.log"))
				if e != nil {
					t.Fatal(e)
				}
				defer log.Close()
				cmd.Stderr = log
				if e = cmd.Start(); e != nil {
					t.Fatal(e)
				}
				scan := bufio.NewScanner(out)
				ready := false
				for scan.Scan() {
					fmt.Fprintln(log, scan.Text())
					if scan.Text() == "P3_READY "+phase {
						ready = true
						break
					}
				}
				if ready && mode == "kill" {
					if e = cmd.Process.Kill(); e != nil {
						t.Fatal(e)
					}
				}
				wait := cmd.Wait()
				if !ready {
					t.Fatal("child did not reach requested cut", wait)
				}
				if phase == "normal-close" {
					if wait != nil {
						t.Fatal(wait)
					}
				} else {
					var exit *exec.ExitError
					if !errors.As(wait, &exit) || (mode == "exit" && exit.ExitCode() != 77) {
						t.Fatal("process failure not injected", wait)
					}
				}
				p3capture(t, root, name+"-before-reopen")
				s = p3open(t, path)
				defer s.Close()
				want, pending := 2, 0
				if phase == "begin" || phase == "write" || phase == "pre-commit" {
					want, pending = 1, 1
				}
				p3integrity(t, s, want)
				state, e := s.State(context.Background())
				if e != nil || state.Revision != identity.Revision(want) || state.PendingTransactions != pending {
					t.Fatal("revision/journal state", state, e)
				}
				if got, e := s.Account(context.Background(), baseline.ID); e != nil || got.Name != "committed-baseline" {
					t.Fatal("acknowledged baseline missing", e)
				}
				if want == 2 {
					var named int
					if e := s.db.QueryRow("SELECT count(*) FROM accounts WHERE name='acknowledged-after-commit'").Scan(&named); e != nil || named != 1 {
						t.Fatal("acknowledged application contents missing", named, e)
					}
				}
				if pending > 0 {
					_, e = s.Transact(context.Background(), state.Revision, actor(t), func(ports.Writer) error { return nil })
					if !codeIs(e, identity.Unavailable) {
						t.Fatal("pending recovery review was bypassed", e)
					}
				}
				p3json(t, name+"-recovered", map[string]any{"integrity_check": "ok", "foreign_key_check_rows": 0, "accounts": want, "state": state, "process_exit": fmt.Sprint(wait), "scope": "process failure only; not OS crash or power loss"})
			})
		}
	}
}

func p3BackupVaultPair(t *testing.T) {
	ctx := context.Background()
	root := p3root(t, "backup-vault")
	key := filepath.Join(root, "vault.key")
	if e := secretvault.InitFile(key); e != nil {
		t.Fatal(e)
	}
	vault, e := secretvault.LoadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	opts := options(t)
	opts.Cipher = vault
	path := filepath.Join(root, "state.db")
	s, e := Open(ctx, path, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	a := account(t)
	cred := access.Credential{ID: newID(t), OwnerAccountID: &a.ID, Kind: access.PSK, Schema: 1, State: "active", Payload: access.PSKPayload{Key: secret.New("synthetic-p3-backup-payload")}, Stamp: identity.NewStamp(time.Now())}
	if _, e = s.Transact(ctx, 0, actor(t), func(w ports.Writer) error {
		if e := w.CreateAccount(a); e != nil {
			return e
		}
		return w.CreateCredential(cred)
	}); e != nil {
		t.Fatal(e)
	}
	restore := filepath.Join(root, "restore")
	if e = privateDirectory(restore); e != nil {
		t.Fatal(e)
	}
	snapshot := filepath.Join(restore, "state.db")
	method := "stopped MaintenanceBackup VACUUM INTO"
	if runtime.GOOS == "linux" {
		if _, e = MaintenanceBackup(ctx, path, snapshot); e == nil {
			t.Fatal("live maintenance backup admitted")
		}
		if e = s.Close(); e != nil {
			t.Fatal(e)
		}
		if _, e = MaintenanceBackup(ctx, path, snapshot); e != nil {
			t.Fatal(e)
		}
	} else {
		if _, e = MaintenanceBackup(ctx, path, snapshot); e == nil {
			t.Fatal("unsupported production maintenance admitted")
		}
		method = "test-only coherent SQLite VACUUM INTO; production Windows backup NOT EXECUTED"
		if _, e = s.db.Exec("VACUUM INTO ?", snapshot); e != nil {
			t.Fatal(e)
		}
		s.Close()
	}
	keyBytes, e := os.ReadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(keyBytes)
	restoreKey := filepath.Join(restore, "vault.key")
	if e = os.WriteFile(restoreKey, keyBytes, 0600); e != nil {
		t.Fatal(e)
	}
	restoredVault, e := secretvault.LoadFile(restoreKey)
	if e != nil {
		t.Fatal(e)
	}
	if restoredVault.KeyID() != vault.KeyID() {
		t.Fatal("snapshot/key identity mismatch")
	}
	opts.Cipher = restoredVault
	s, e = Open(ctx, snapshot, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.RevealCredential(ctx, cred.ID)
	if e != nil || got.Payload.(access.PSKPayload).Key.Reveal() != cred.Payload.(access.PSKPayload).Key.Reveal() {
		t.Fatal("paired restore decrypt failed", e)
	}
	restoredAccount := p3account(t, s, 1, "restored-write")
	p3integrity(t, s, 2)
	s.Close()
	s, e = Open(ctx, snapshot, opts)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RevealCredential(ctx, cred.ID); e != nil {
		t.Fatal(e)
	}
	p3integrity(t, s, 2)
	if got, e := s.Account(ctx, restoredAccount.ID); e != nil || got.Name != restoredAccount.Name {
		t.Fatal("restored new write did not survive restart", e)
	}
	raw, e := os.ReadFile(snapshot)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("synthetic-p3-backup-payload")) {
		t.Fatal("plaintext credential persisted")
	}
	wrong, e := secretvault.New("incorrect-synthetic-key", bytes.Repeat([]byte{13}, 32))
	if e != nil {
		t.Fatal(e)
	}
	s.options.Cipher = wrong
	if _, e = s.RevealCredential(ctx, cred.ID); e == nil {
		t.Fatal("wrong vault key accepted")
	}
	s.options.Cipher = nil
	if _, e = s.RevealCredential(ctx, cred.ID); e == nil {
		t.Fatal("missing vault key accepted")
	}
	s.Close()
	p3json(t, "backup-vault", map[string]any{"method": method, "schema": 8, "paired_key_id": vault.KeyID(), "restore_read_write_reopen": "PASS", "wrong_and_missing_key_rejected": true, "integrity_check": "ok", "foreign_key_check_rows": 0})
}

func p3IndependentWALTail(t *testing.T) {
	original := filepath.Join(os.Getenv("P3_EVIDENCE"), "after-commit-kill-before-reopen")
	main, e := os.ReadFile(filepath.Join(original, "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	wal, e := os.ReadFile(filepath.Join(original, "state.db-wal"))
	if e != nil || len(wal) < 32 {
		t.Fatal("missing genuine committed WAL", e)
	}
	page := int(binary.BigEndian.Uint32(wal[8:12]))
	if page == 1 {
		page = 65536
	}
	frame := page + 24
	if (len(wal)-32)%frame != 0 {
		t.Fatal("unaligned captured WAL")
	}
	for _, fault := range []string{"unchanged", "partial-uncommitted-tail", "truncated-last-frame", "last-frame-checksum"} {
		t.Run(fault, func(t *testing.T) {
			root := p3root(t, "wal-"+fault)
			path := filepath.Join(root, "state.db")
			damaged := append([]byte(nil), wal...)
			switch fault {
			case "partial-uncommitted-tail":
				damaged = append(damaged, []byte{1, 2, 3, 4, 5, 6, 7}...)
			case "truncated-last-frame":
				damaged = damaged[:len(damaged)-page/2]
			case "last-frame-checksum":
				damaged[len(damaged)-frame+16] ^= 1
			}
			if e := os.WriteFile(path, main, 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(path+"-wal", damaged, 0600); e != nil {
				t.Fatal(e)
			}
			p3capture(t, root, "independent-wal-"+fault+"-original")
			db, e := sql.Open("sqlite", path)
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			var version, check string
			var count int
			e = db.QueryRow("SELECT count(*) FROM accounts").Scan(&count)
			integrity := db.QueryRow("PRAGMA integrity_check").Scan(&check)
			db.QueryRow("SELECT sqlite_version()").Scan(&version)
			qualifier := "QUALIFIED_WITH_LIMITATIONS"
			if e != nil || integrity != nil || check != "ok" || count != 2 {
				qualifier = "NOT_QUALIFIED"
			}
			application := map[string]any{}
			if e := db.Close(); e != nil {
				t.Fatal(e)
			}
			store, openErr := Open(context.Background(), path, options(t))
			application["store_open_error"] = fmt.Sprint(openErr)
			if (fault == "unchanged" || fault == "partial-uncommitted-tail") && openErr != nil {
				t.Fatal("valid WAL application reopen failed", openErr)
			}
			if openErr == nil {
				state, stateErr := store.State(context.Background())
				if stateErr != nil {
					store.Close()
					t.Fatal(stateErr)
				}
				application["state"] = state
				application["state_error"] = fmt.Sprint(stateErr)
				if count != 2 {
					_, mutationErr := store.Transact(context.Background(), state.Revision, actor(t), func(ports.Writer) error { return nil })
					application["mutation_rejected"] = mutationErr != nil
					if !codeIs(mutationErr, identity.Unavailable) {
						store.Close()
						t.Fatal("damaged WAL state admitted mutation despite unresolved journal")
					}
					application["mutation_error"] = fmt.Sprint(mutationErr)
				}
				if e := store.Close(); e != nil {
					t.Fatal(e)
				}
			}
			p3json(t, "wal-"+fault, map[string]any{"application": application, "sqlite": version, "accounts": count, "acknowledged_accounts": 2, "query_error": fmt.Sprint(e), "integrity_check": check, "integrity_error": fmt.Sprint(integrity), "qualification": qualifier, "note": "native SQLite diagnostic; no P1-B guard or production behavior change"})
			if (fault == "unchanged" || fault == "partial-uncommitted-tail") && (e != nil || check != "ok" || count != 2) {
				t.Fatal("valid committed prefix was lost", count, e, integrity)
			}
			if e = db.Close(); e != nil && !strings.Contains(e.Error(), "closed") {
				t.Fatal(e)
			}
			p3capture(t, root, "independent-wal-"+fault+"-recovered")
		})
	}
}
