package sqlite

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

// runtimeBoundary checks stored intent before any forward migration. Retired
// experimental records remain intact and require an operator to remove them
// using the old build. Disabled records are rejected too; none are downgraded.
func runtimeBoundary(ctx context.Context, q queryer) error {
	checks := []struct{ table, predicate string }{
		{"inbounds", `engine='xray' OR json_type(settings,'$.engine_options') IS NOT NULL OR json_type(settings,'$.finalmask') IS NOT NULL OR json_type(settings,'$.sudoku') IS NOT NULL`},
		{"client_outbounds", `json_extract(document,'$.engine')='xray'`},
		{"remote_nodes", `json_extract(document,'$.engine')='xray' OR json_type(document,'$.options.data.engine_options') IS NOT NULL OR json_type(document,'$.options.data.finalmask') IS NOT NULL OR json_type(document,'$.options.data.sudoku') IS NOT NULL`},
		{"client_management_profiles", `EXISTS (SELECT 1 FROM json_each(document,'$.providers') WHERE json_extract(value,'$.engine')='xray')`},
	}
	for _, check := range checks {
		var exists, retired int
		if err := q.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", check.table).Scan(&exists); err != nil {
			return storageError(err)
		}
		if exists == 0 {
			continue
		}
		if err := q.QueryRowContext(ctx, "SELECT count(*) FROM "+check.table+" WHERE "+check.predicate).Scan(&retired); err != nil {
			return identity.Err(identity.Corrupt, "runtime boundary state cannot be validated")
		}
		if retired != 0 {
			return identity.Err(identity.UnsupportedEngineForProtocol, identity.RetiredRuntimeStateMessage)
		}
	}
	return nil
}

// VerifyRuntimeBoundary reads an owned, stopped-service backup without migrating
// or initializing it. The installer calls this before replacing any files.
func VerifyRuntimeBoundary(ctx context.Context, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return identity.Err(identity.Invalid, "invalid runtime boundary database path")
	}
	if err := safeFile(path); err != nil {
		return err
	}
	uriPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return storageError(err)
	}
	defer db.Close()
	return runtimeBoundary(ctx, db)
}
