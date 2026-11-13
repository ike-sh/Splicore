package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

// Each fault has separate native-SQLite and application copies. Opening/closing
// the native probe must never checkpoint or otherwise alter the application's
// input WAL. An external acknowledged row/revision oracle is kept by this test;
// Schema8 itself has no independent durable oracle outside that same WAL.
func p31WALSafetyBoundary(t *testing.T) {
	ctx := context.Background()
	for _, operation := range []string{"after-commit", "after-runtime-commit"} {
		t.Run(operation, func(t *testing.T) {
			original := filepath.Join(os.Getenv("P3_EVIDENCE"), operation+"-kill-before-reopen")
			main, err := os.ReadFile(filepath.Join(original, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			wal, err := os.ReadFile(filepath.Join(original, "state.db-wal"))
			if err != nil {
				t.Fatal(err)
			}
			mainHash, walHash := sha256.Sum256(main), sha256.Sum256(wal)
			page := int(binary.BigEndian.Uint32(wal[8:12]))
			if page == 1 {
				page = 65536
			}
			frame := page + 24
			if len(wal) < 32+frame || (len(wal)-32)%frame != 0 {
				t.Fatal("unaligned genuine WAL")
			}
			var commits []int
			for off := 32; off+frame <= len(wal); off += frame {
				if binary.BigEndian.Uint32(wal[off+4:off+8]) != 0 {
					commits = append(commits, off)
				}
			}
			if len(commits) < 2 || commits[len(commits)-1] != len(wal)-frame {
				t.Fatal("fixture must contain both pending-journal commit and final acknowledged business commit", commits)
			}
			// A verified intact snapshot is established before touching any fault
			// copy. It contains the very two acknowledged rows checked below.
			backupRoot := p3root(t, "boundary-backup-"+operation)
			backupSource := filepath.Join(backupRoot, "state.db")
			p31WALCopy(t, backupSource, main, wal)
			s := p3open(t, backupSource)
			p3integrity(t, s, 2)
			backup := filepath.Join(backupRoot, "verified.db")
			if runtime.GOOS == "linux" {
				s.Close()
				if _, err = MaintenanceBackup(ctx, backupSource, backup); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err = s.db.Exec("VACUUM INTO ?", backup); err != nil {
					t.Fatal(err)
				}
				s.Close()
			}
			backupBytes, err := os.ReadFile(backup)
			if err != nil {
				t.Fatal(err)
			}
			backupHash := sha256.Sum256(backupBytes)
			if err = os.WriteFile(filepath.Join(os.Getenv("P3_EVIDENCE"), "boundary-"+operation+"-verified-backup.db"), backupBytes, 0600); err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"unchanged", "partial-uncommitted-tail", "truncated-committed-frame", "committed-frame-checksum", "pending-journal-commit-checksum"} {
				t.Run(fault, func(t *testing.T) {
					damaged := append([]byte(nil), wal...)
					affected := commits[len(commits)-1]
					switch fault {
					case "partial-uncommitted-tail":
						damaged = append(damaged, 1, 2, 3, 4, 5, 6, 7)
					case "truncated-committed-frame":
						damaged = damaged[:len(damaged)-page/2]
					case "committed-frame-checksum":
						damaged[affected+16] ^= 1
					case "pending-journal-commit-checksum":
						affected = commits[0]
						damaged[affected+16] ^= 1
					}
					prefix := operation + "-" + fault
					nativePath := filepath.Join(p3root(t, "boundary-native-"+prefix), "state.db")
					appRoot := p3root(t, "boundary-app-"+prefix)
					appPath := filepath.Join(appRoot, "state.db")
					p31WALCopy(t, nativePath, main, damaged)
					p31WALCopy(t, appPath, main, damaged)
					p3capture(t, appRoot, "boundary-"+prefix+"-damaged-input")
					db, err := sql.Open("sqlite", nativePath)
					if err != nil {
						t.Fatal(err)
					}
					var check string
					if err = db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil {
						t.Fatal(err)
					}
					var fkRows int
					if err = db.QueryRow("SELECT count(*) FROM pragma_foreign_key_check").Scan(&fkRows); err != nil || fkRows != 0 || check != "ok" {
						t.Fatal("native structural checks", check, fkRows, err)
					}
					var nativeRows, revision, pending int
					if err = db.QueryRow(`SELECT (SELECT count(*) FROM accounts),(SELECT committed_revision FROM settings WHERE singleton=1),(SELECT count(*) FROM transactions WHERE state='pending')`).Scan(&nativeRows, &revision, &pending); err != nil {
						t.Fatal(err)
					}
					if err = db.Close(); err != nil {
						t.Fatal(err)
					}
					p3capture(t, filepath.Dir(nativePath), "boundary-"+prefix+"-native-recovered")
					// The independent probe's close cannot repair the application input.
					appWAL, err := os.ReadFile(appPath + "-wal")
					if err != nil || sha256.Sum256(appWAL) != sha256.Sum256(damaged) {
						t.Fatal("native probe changed application fault copy", err)
					}
					store := p3open(t, appPath)
					p3integrity(t, store, nativeRows)
					state, err := store.State(ctx)
					if err != nil {
						t.Fatal(err)
					}
					var acknowledged int
					if err = store.db.QueryRow("SELECT count(*) FROM accounts WHERE name IN ('committed-baseline','acknowledged-after-commit')").Scan(&acknowledged); err != nil {
						t.Fatal(err)
					}
					valid := fault == "unchanged" || fault == "partial-uncommitted-tail"
					if valid {
						p3integrity(t, store, 2)
						if acknowledged != 2 || state.Revision != 2 || state.PendingTransactions != 0 {
							t.Fatal("valid committed application state lost", state)
						}
					} else {
						if acknowledged != 1 || state.Revision != 1 {
							t.Fatal("committed-frame damage did not reach expected earlier generation", acknowledged, state)
						}
					}
					admissionBefore := map[string]any{}
					if !valid {
						admissionBefore = p31WriteAdmission(t, store, state)
					} else {
						admissionBefore = map[string]any{"qualification": "NOT_EXECUTED", "reason": "intact-state writes are covered by normal transactions and the verified-backup restore"}
					}
					// This is the same recovery entry used by the application startup.
					// Preserve the raw input first: recovery of a pending runtime
					// operation can erase the only surviving symptom of lost commit.
					if err = store.RecoverPending(ctx); err != nil {
						t.Fatal(err)
					}
					afterRecovery, err := store.State(ctx)
					if err != nil {
						t.Fatal(err)
					}
					admissionAfter := map[string]any{}
					if !valid {
						admissionAfter = p31WriteAdmission(t, store, afterRecovery)
					} else {
						admissionAfter = admissionBefore
					}
					store.Close()
					p3capture(t, appRoot, "boundary-"+prefix+"-after-application-recovery")
					restoreRoot := p3root(t, "boundary-restore-"+prefix)
					restorePath := filepath.Join(restoreRoot, "state.db")
					if err = os.WriteFile(restorePath, backupBytes, 0600); err != nil {
						t.Fatal(err)
					}
					restored := p3open(t, restorePath)
					p3integrity(t, restored, 2)
					var restoredAcknowledged int
					if err = restored.db.QueryRow("SELECT count(*) FROM accounts WHERE name IN ('committed-baseline','acknowledged-after-commit')").Scan(&restoredAcknowledged); err != nil || restoredAcknowledged != 2 {
						t.Fatal("backup did not recover acknowledged contents", restoredAcknowledged, err)
					}
					added := p3account(t, restored, 2, "verified-backup-new-write")
					restored.Close()
					p3capture(t, restoreRoot, "boundary-"+prefix+"-after-backup-restore")
					restored = p3open(t, restorePath)
					p3integrity(t, restored, 3)
					if got, err := restored.Account(ctx, added.ID); err != nil || got.Name != added.Name {
						t.Fatal("backup write/restart mismatch", err)
					}
					restored.Close()
					dataQualification := "NOT_QUALIFIED"
					if valid {
						dataQualification = "QUALIFIED_WITH_LIMITATIONS"
					}
					p3json(t, "boundary-"+prefix, map[string]any{
						"sqlite_structural_integrity":             map[string]any{"integrity_check": check, "foreign_key_check_rows": fkRows, "qualification": "QUALIFIED_WITH_LIMITATIONS"},
						"acknowledged_application_data":           map[string]any{"expected_rows": 2, "native_rows": nativeRows, "actual_named_rows": acknowledged, "expected_revision": 2, "native_revision": revision, "application_state": state, "qualification": dataQualification},
						"write_admission_before_startup_recovery": admissionBefore, "write_admission_after_startup_recovery": admissionAfter, "state_after_startup_recovery": afterRecovery,
						"verified_backup_restore":                 map[string]any{"qualification": "QUALIFIED_WITH_LIMITATIONS", "same_acknowledged_rows": 2, "new_write_and_restart": true, "backup_sha256": fmt.Sprintf("%x", backupHash), "vault_key_pair_separate_evidence": "backup-vault.json", "production_windows_backup": "NOT_EXECUTED"},
						"wal_frame_proof":                         map[string]any{"page_size": page, "frame_size": frame, "commit_frame_offsets": commits, "affected_frame_offset": affected, "affected_commit_db_pages": binary.BigEndian.Uint32(wal[affected+4 : affected+8]), "original_wal_sha256": fmt.Sprintf("%x", walHash), "damaged_wal_sha256": fmt.Sprintf("%x", sha256.Sum256(damaged))},
						"COMMITTED_WAL_MEDIA_CORRUPTION_RECOVERY": "NOT_QUALIFIED", "note": "Structural validity, acknowledged data, write admission and backup restore are independent. Known write-admission blind spots block PR admission even if diagnostic assertions pass.",
					})
				})
			}
			afterMain, err := os.ReadFile(filepath.Join(original, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			afterWAL, err := os.ReadFile(filepath.Join(original, "state.db-wal"))
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(afterMain) != mainHash || sha256.Sum256(afterWAL) != walHash {
				t.Fatal("original committed evidence changed")
			}
		})
	}
}

func p31WALCopy(t *testing.T, path string, main, wal []byte) {
	t.Helper()
	if err := os.WriteFile(path, main, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"-wal", wal, 0600); err != nil {
		t.Fatal(err)
	}
}

func p31WriteAdmission(t *testing.T, s *Store, state ports.State) map[string]any {
	t.Helper()
	ctx := context.Background()
	called := false
	a := account(t)
	a.Name = "damaged-copy-write-canary"
	var before, after int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM transactions").Scan(&before); err != nil {
		t.Fatal(err)
	}
	_, err := s.Transact(ctx, state.Revision, actor(t), func(w ports.Writer) error { called = true; return w.CreateAccount(a) })
	if queryErr := s.db.QueryRowContext(ctx, "SELECT count(*) FROM transactions").Scan(&after); queryErr != nil {
		t.Fatal(queryErr)
	}
	blocked := codeIs(err, identity.Unavailable) && !called
	businessQualification := "NOT_QUALIFIED"
	if blocked {
		businessQualification = "QUALIFIED_WITH_LIMITATIONS"
	}
	qualification := "NOT_QUALIFIED"
	if blocked && before == after {
		qualification = "QUALIFIED_WITH_LIMITATIONS"
	}
	if state.PendingTransactions > 0 && !blocked {
		t.Fatal("pending journal protection regressed", err, called)
	}
	t.Logf("WAL_WRITE_BOUNDARY pending=%d callback_called=%t journal_rows_before=%d after=%d error=%v qualification=%s", state.PendingTransactions, called, before, after, err, qualification)
	return map[string]any{"qualification": qualification, "business_write_qualification": businessQualification, "journal_rows_before": before, "journal_rows_after": after, "callback_called": called, "mutation_rejected": err != nil, "mutation_error": fmt.Sprint(err)}
}
