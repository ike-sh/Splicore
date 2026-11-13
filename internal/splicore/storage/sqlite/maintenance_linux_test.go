package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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
	if _, err = MaintenanceBackup(ctx, source, dest); err == nil {
		t.Fatal("snapshot overwrite accepted")
	}
}

func TestMaintenancePendingSourcePreserved(t *testing.T) {
	s, source := newStore(t)
	ctx := context.Background()
	if _, err := s.BeginOperation(ctx, 0, actor(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before := admissionFiles(t, source)
	destination := filepath.Join(filepath.Dir(source), "must-not-be-created.db")
	if _, err := MaintenanceBackup(ctx, source, destination); err == nil {
		t.Fatal("ambiguous pending source exported as a valid backup")
	}
	after := admissionFiles(t, source)
	admissionEvidence(t, "before-maintenance-open", before, nil)
	admissionEvidence(t, "after-maintenance-close", after, nil)
	if !reflect.DeepEqual(before["state.db"], after["state.db"]) {
		t.Fatal("rejected maintenance modified source database")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("rejected maintenance created destination", err)
	}
	// The maintenance API opens and closes its own SQLite reader. Record WAL
	// and SHM creation/deletion separately from SQL-level source mutations.
	t.Logf("reader open/close WAL identical=%t SHM identical=%t", reflect.DeepEqual(before["state.db-wal"], after["state.db-wal"]), reflect.DeepEqual(before["state.db-shm"], after["state.db-shm"]))
}
