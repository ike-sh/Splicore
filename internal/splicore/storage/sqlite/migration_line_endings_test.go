package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationChecksumsAreLineEndingStable(t *testing.T) {
	for _, step := range migrations() {
		canonical := canonicalMigrationSQL(step.SQL)
		lf := migrationDigest(canonical)
		crlf := migrationDigest(strings.ReplaceAll(canonical, "\n", "\r\n"))
		if checksum(step) != lf || !migrationChecksumMatches(step, lf) || !migrationChecksumMatches(step, crlf) {
			t.Fatalf("migration %d line-ending identity is not portable", step.Version)
		}
		if migrationChecksumMatches(step, migrationDigest(canonical+"-- changed\n")) {
			t.Fatalf("migration %d accepted changed SQL", step.Version)
		}
	}
}

func TestLegacyBaselineAcceptsHistoricalWindowsMigrationDigests(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "state.db")
	store, err := Open(ctx, path, options(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path + witnessSuffix); err != nil {
		t.Fatal(err)
	}
	u, err := writableExistingDatabaseURL(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", u)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range migrations() {
		legacyWindows := migrationDigest(strings.ReplaceAll(canonicalMigrationSQL(step.SQL), "\n", "\r\n"))
		if _, err = db.Exec("UPDATE schema_migrations SET checksum=? WHERE version=?", legacyWindows, step.Version); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	inspection, err := EstablishCommitWitness(ctx, path, true)
	if err != nil || inspection.Status != "verified" || inspection.Lineage != witnessLineageLegacy {
		t.Fatal("historical Windows database did not establish an explicit baseline", inspection, err)
	}
	reopened, err := Open(ctx, path, options(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
