package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type migration struct {
	Version int
	Name    string
	SQL     string
}

func migrations() []migration {
	b, _ := migrationFiles.ReadFile("migrations/0001_initial.sql")
	c, _ := migrationFiles.ReadFile("migrations/0002_snell.sql")
	d, _ := migrationFiles.ReadFile("migrations/0003_password.sql")
	e, _ := migrationFiles.ReadFile("migrations/0004_private_key.sql")
	f, _ := migrationFiles.ReadFile("migrations/0005_client_runtime.sql")
	g, _ := migrationFiles.ReadFile("migrations/0006_network_profiles.sql")
	h, _ := migrationFiles.ReadFile("migrations/0007_host_integration.sql")
	return []migration{{1, "0001_initial", string(b)}, {2, "0002_snell", string(c)}, {3, "0003_password", string(d)}, {4, "0004_private_key", string(e)}, {5, "0005_client_runtime", string(f)}, {6, "0006_network_profiles", string(g)}, {7, "0007_host_integration", string(h)}}
}

func checksum(m migration) string { s := sha256.Sum256([]byte(m.SQL)); return hex.EncodeToString(s[:]) }

// migrate owns all schema changes and applies each numbered step transactionally.
func migrate(ctx context.Context, db *sql.DB, steps []migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&count); err != nil {
		return storageError(err)
	}
	current := 0
	fresh := count == 0
	if count > 0 {
		rows, err := tx.QueryContext(ctx, "SELECT version,name,checksum FROM schema_migrations ORDER BY version")
		if err != nil {
			return identity.Err(identity.Corrupt, "missing migration history")
		}
		for rows.Next() {
			var version int
			var name, sum string
			if err = rows.Scan(&version, &name, &sum); err != nil {
				rows.Close()
				return storageError(err)
			}
			if version > len(steps) {
				rows.Close()
				return identity.Err(identity.Unavailable, "database schema is newer than this executable")
			}
			if version != current+1 || version < 1 || steps[version-1].Version != version || steps[version-1].Name != name || checksum(steps[version-1]) != sum {
				rows.Close()
				return identity.Err(identity.Corrupt, "migration history checksum or sequence mismatch")
			}
			current = version
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return storageError(err)
		}
		if current == 0 {
			return identity.Err(identity.Corrupt, "empty migration history in existing database")
		}
		var product, schema string
		if tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='product'").Scan(&product) != nil || product != "Splicore" || tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='db_schema'").Scan(&schema) != nil || schema != strconv.Itoa(current) {
			return identity.Err(identity.Corrupt, "invalid product or schema metadata")
		}
	}
	for _, m := range steps[current:] {
		if m.Version != current+1 {
			return identity.Err(identity.Invalid, "invalid migration sequence")
		}
		if _, err = tx.ExecContext(ctx, m.SQL); err != nil {
			return identity.Err(identity.Corrupt, "forward migration failed; transaction rolled back")
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations VALUES(?,?,?,?)", m.Version, m.Name, checksum(m), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return storageError(err)
		}
		if _, err = tx.ExecContext(ctx, "UPDATE metadata SET value=? WHERE key='db_schema'", fmt.Sprint(m.Version)); err != nil {
			return storageError(err)
		}
		current = m.Version
	}
	if current != len(steps) {
		return identity.Err(identity.Corrupt, "incomplete migration history")
	}
	if fresh {
		id, err := identity.NewID()
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO nodes VALUES(?,?)", id, utc(time.Now())); err != nil {
			return storageError(err)
		}
	}
	if err = integrity(ctx, tx); err != nil {
		return err
	}
	return storageError(tx.Commit())
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func integrity(ctx context.Context, q queryer) error {
	var result string
	if q.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result) != nil || result != "ok" {
		return identity.Err(identity.Corrupt, "database integrity check failed")
	}
	rows, err := q.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return storageError(err)
	}
	defer rows.Close()
	if rows.Next() {
		return identity.Err(identity.Corrupt, "database foreign key check failed")
	}
	return storageError(rows.Err())
}
