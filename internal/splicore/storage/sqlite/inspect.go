package sqlite

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

// Inspect opens existing committed state for read-only validation. It never
// initializes, migrates, recovers pending operations or acquires writer ownership.
// SQLite's normal read-only WAL reader semantics remain unchanged.
func Inspect(ctx context.Context, path string, opts Options) (*Store, error) {
	dir := filepath.Dir(path)
	info, statErr := os.Stat(dir)
	if !filepath.IsAbs(path) || statErr != nil || !info.IsDir() || privateDirectory(dir) != nil {
		return nil, identity.Err(identity.Invalid, "private directory owner or permissions invalid")
	}
	for _, suffix := range []string{"", "-wal", "-shm", ".lock"} {
		if err := safeFile(path + suffix); err != nil {
			return nil, err
		}
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	if filepath.VolumeName(path) != "" {
		u.Path = "/" + u.Path
	}
	u.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)", "busy_timeout(5000)"}}.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, storageError(err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, options: opts}
	fail := func(err error) (*Store, error) { _ = s.Close(); return nil, err }
	var integrity string
	if db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity) != nil || integrity != "ok" {
		return fail(identity.Err(identity.Corrupt, "invalid or corrupt committed state"))
	}
	state, err := s.State(ctx)
	if err != nil {
		return fail(err)
	}
	if state.PendingTransactions != 0 {
		return fail(identity.Err(identity.Unavailable, "pending operations require startup recovery"))
	}
	return s, nil
}
