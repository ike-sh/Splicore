package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
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
