package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/sagernet/sing-box/internal/splicore/version"
)

// MaintenanceBackup acquires the installation lock without initialization or
// migration. The service must be stopped. VACUUM INTO makes a coherent SQLite
// snapshot; callers must preserve the matching external key separately.
func MaintenanceBackup(ctx context.Context, source, destination string) (int, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("production backup requires Linux")
	}
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || source == destination {
		return 0, fmt.Errorf("invalid backup paths")
	}
	if err := maintenanceFile(source); err != nil {
		return 0, err
	}
	if err := maintenanceFile(source + ".lock"); err != nil {
		return 0, err
	}
	lock, err := os.OpenFile(source+".lock", os.O_RDWR, 0)
	if err != nil {
		return 0, fmt.Errorf("installation lock unavailable")
	}
	defer lock.Close()
	if err = lockFile(lock); err != nil {
		return 0, fmt.Errorf("stop the service before backup")
	}
	defer unlockFile(lock)
	if err = privateDirectory(filepath.Dir(destination)); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 0, fmt.Errorf("backup destination must be new")
	}
	f.Close()
	complete := false
	defer func() {
		if !complete {
			os.Remove(destination)
		}
	}()
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(source)}
	q := url.Values{"mode": []string{"ro"}, "_pragma": []string{"busy_timeout(5000)"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return 0, fmt.Errorf("backup database unavailable")
	}
	defer db.Close()
	var integrity, schema string
	if db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity) != nil || integrity != "ok" {
		return 0, fmt.Errorf("backup source integrity failed")
	}
	if db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='db_schema'").Scan(&schema) != nil {
		return 0, fmt.Errorf("backup source schema unavailable")
	}
	n, err := strconv.Atoi(schema)
	if err != nil || n < 1 || n > version.DatabaseSchema {
		return 0, fmt.Errorf("backup source schema incompatible")
	}
	if _, err = db.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		return 0, fmt.Errorf("SQLite snapshot failed")
	}
	if err = maintenanceFile(destination); err != nil {
		return 0, err
	}
	f, err = os.OpenFile(destination, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if err = f.Sync(); err != nil {
		return 0, err
	}
	complete = true
	return n, nil
}
