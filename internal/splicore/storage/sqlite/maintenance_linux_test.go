package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func TestMaintenanceBackupStoppedConsistentSnapshot(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	source := filepath.Join(dir, "state.db")
	dest := filepath.Join(dir, "snapshot.db")
	ctx := context.Background()
	s, err := Open(ctx, source, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = MaintenanceBackup(ctx, source, dest); err == nil {
		t.Fatal("online snapshot ignored installation lock")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	schema, err := MaintenanceBackup(ctx, source, dest)
	if err != nil || schema != version.DatabaseSchema {
		t.Fatal(schema, err)
	}
	db, err := sql.Open("sqlite", dest)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var check string
	if err = db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		t.Fatal(check, err)
	}
	inspection, err := InspectCommitWitness(ctx, dest)
	if err != nil || inspection.Status != "verified" || !inspection.HistoricalProof {
		t.Fatal("backup witness mismatch", inspection, err)
	}
	if _, err = MaintenanceBackup(ctx, source, dest); err == nil {
		t.Fatal("snapshot overwrite accepted")
	}
}

func TestMaintenanceBackupWitnessBoundaries(t *testing.T) {
	ctx := context.Background()
	newSource := func(t *testing.T) (string, []byte) {
		t.Helper()
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "state.db")
		s, err := Open(ctx, path, options(t))
		if err != nil {
			t.Fatal(err)
		}
		witness, err := os.ReadFile(path + witnessSuffix)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		return path, witness
	}

	t.Run("legacy-unwitnessed-snapshot-remains-unwitnessed", func(t *testing.T) {
		source, _ := newSource(t)
		if err := os.Remove(source + witnessSuffix); err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(filepath.Dir(source), "legacy-snapshot.db")
		if _, err := MaintenanceBackup(ctx, source, destination); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(destination + witnessSuffix); !os.IsNotExist(err) {
			t.Fatal("legacy backup gained implicit witness", err)
		}
		inspection, err := InspectCommitWitness(ctx, destination)
		if err != nil || inspection.Status != "witness_missing" || inspection.HistoricalProof {
			t.Fatal(inspection, err)
		}
	})

	for _, fault := range []string{"pending", "corrupt", "rollback"} {
		t.Run(fault+"-witness-blocks-backup", func(t *testing.T) {
			source, initial := newSource(t)
			switch fault {
			case "pending":
				if err := os.WriteFile(source+pendingSuffix, []byte(`{"partial":`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				initial[len(initial)/2] ^= 1
				if err := os.WriteFile(source+witnessSuffix, initial, 0o600); err != nil {
					t.Fatal(err)
				}
			case "rollback":
				s, err := Open(ctx, source, options(t))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.Transact(ctx, 0, actor(t), func(w ports.Writer) error { return w.CreateAccount(account(t)) }); err != nil {
					s.Close()
					t.Fatal(err)
				}
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(source+witnessSuffix, initial, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			destination := filepath.Join(filepath.Dir(source), fault+"-snapshot.db")
			if _, err := MaintenanceBackup(ctx, source, destination); err == nil {
				t.Fatal("unverified source was backed up")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatal("rejected backup left destination", err)
			}
		})
	}
}

func TestMaintenanceSnapshotRootAcceptsServiceOwnedDatabase(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only ownership boundary")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "state.db")
	if err := os.WriteFile(source, []byte("service-owned-database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(source, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	snapshot, cleanup, err := readOnlyMaintenanceSnapshot(source)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(snapshot)
	if err != nil || string(data) != "service-owned-database" {
		t.Fatal("maintenance snapshot changed the service-owned source", err)
	}
}
