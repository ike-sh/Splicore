package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func TestRetiredRuntimeUpgradeRetainsState(t *testing.T) {
	for _, tc := range []struct{ name, table, insert string }{
		{"inbound", "inbounds", `CREATE TABLE inbounds(engine TEXT,settings TEXT); INSERT INTO inbounds VALUES('xray','{}')`},
		{"mask", "inbounds", `CREATE TABLE inbounds(engine TEXT,settings TEXT); INSERT INTO inbounds VALUES('native','{"engine_options":{"finalmask":{}}}')`},
		{"outbound", "client_outbounds", `INSERT INTO client_outbounds VALUES('retired',NULL,'{"engine":"xray"}')`},
		{"node_mask", "remote_nodes", `INSERT INTO remote_nodes VALUES('retired','{"options":{"data":{"finalmask":{"tcp":[{"type":"sudoku"}]}}}}')`},
		{"provider", "client_management_profiles", `INSERT INTO client_management_profiles VALUES(1,'{"providers":[{"engine":"xray"}]}')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "state.db")
			if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			// Build a real historical database through immutable migrations, then
			// add a minimal retired record. Outbound fixtures bypass unrelated FK
			// constraints only because rejection precedes integrity/migration.
			if err = migrate(ctx, db, migrations()[:4]); err != nil {
				t.Fatal(err)
			}
			if tc.table == "inbounds" {
				_, err = db.Exec("DROP TABLE inbounds")
			} else if tc.table == "client_outbounds" {
				_, err = db.Exec("CREATE TABLE client_outbounds(id TEXT,node_id TEXT,document TEXT)")
			} else if tc.table == "remote_nodes" {
				_, err = db.Exec("CREATE TABLE remote_nodes(id TEXT,document TEXT)")
			} else {
				_, err = db.Exec("CREATE TABLE client_management_profiles(singleton INTEGER,document TEXT)")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(tc.insert); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if err = os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var typed *identity.Error
			if err = VerifyRuntimeBoundary(ctx, path); !errors.As(err, &typed) || typed.Code != identity.UnsupportedEngineForProtocol {
				t.Fatal("retired state diagnostic", err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if err = migrate(ctx, db, migrations()); !errors.As(err, &typed) || typed.Code != identity.UnsupportedEngineForProtocol {
				t.Fatal("migration diagnostic", err)
			}
			var version int
			if err = db.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 4 {
				t.Fatal("history changed", err, version)
			}
			var count int
			if err = db.QueryRow("SELECT count(*) FROM " + tc.table).Scan(&count); err != nil || count != 1 {
				t.Fatal("state lost", err, count)
			}
			db.Close()
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("rejected migration changed database")
			}
		})
	}
}

func TestNativeOnlyHistoricalUpgrade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, db, migrations()[:4]); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = VerifyRuntimeBoundary(ctx, path); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	state, err := s.State(ctx)
	if err != nil || state.Schema != 8 {
		t.Fatal("native upgrade", err, state.Schema)
	}
}
