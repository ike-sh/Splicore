package sqlite

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/ports"
)

// Context is an existing I/O seam. The fault triggers when backup has acquired
// its installation lock and created the private destination, before querying
// the source. No timer, production hook or host filesystem is involved.
type phase15BackupCrashContext struct {
	context.Context
	destination string
}

func (c phase15BackupCrashContext) Err() error {
	if _, err := os.Stat(c.destination); err == nil {
		os.Exit(77)
	}
	return c.Context.Err()
}
func TestPhase15ProcessBackupCrashPreservesSource(t *testing.T) {
	if root := os.Getenv("SPLICORE_PHASE15_BACKUP_ROOT"); root != "" {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, err := MaintenanceBackup(phase15BackupCrashContext{ctx, filepath.Join(root, "interrupted.db")}, filepath.Join(root, "state.db"), filepath.Join(root, "interrupted.db"))
		t.Fatal("backup fault did not execute", err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "state.db")
	s, err := Open(context.Background(), source, options(t))
	if err != nil {
		t.Fatal(err)
	}
	a := account(t)
	if _, err = s.Transact(context.Background(), 0, actor(t), func(w ports.Writer) error { return w.CreateAccount(a) }); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPhase15ProcessBackupCrashPreservesSource$")
	cmd.Env = append(os.Environ(), "SPLICORE_PHASE15_BACKUP_ROOT="+root)
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 77 {
		t.Fatalf("fault not reached: %v\n%s", err, output)
	}
	partial, err := os.Stat(filepath.Join(root, "interrupted.db"))
	if err != nil || partial.Size() != 0 {
		t.Fatal("fault was not at private destination creation", err)
	}
	recovered, err := Open(ctx, source, options(t))
	if err != nil {
		t.Fatal(err)
	}
	state, err := recovered.State(ctx)
	if err != nil || state.Revision != 1 || state.PendingTransactions != 0 {
		t.Fatal("backup replaced authority", err)
	}
	if _, err = recovered.Account(ctx, a.ID); err != nil {
		t.Fatal("source data lost", err)
	}
	if err = recovered.Close(); err != nil {
		t.Fatal(err)
	}
	// An interrupted explicit output is preserved and cannot silently overwrite.
	if _, err = MaintenanceBackup(ctx, source, filepath.Join(root, "interrupted.db")); err == nil {
		t.Fatal("partial backup overwritten")
	}
	if _, err = MaintenanceBackup(ctx, source, filepath.Join(root, "fresh.db")); err != nil {
		t.Fatal("new backup after crash failed", err)
	}
}
