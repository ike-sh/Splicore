package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"golang.org/x/sys/windows"
)

func TestWindowsLockedWitnessReplacementFailsClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "state.db")
	var sealed atomic.Int32
	opts := options(t)
	opts.OnIntegrityFailure = func() { sealed.Add(1) }
	store, err := Open(ctx, path, opts)
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path + witnessSuffix)
	if err != nil {
		t.Fatal(err)
	}
	// Permit the admission read but deliberately deny delete sharing, which is
	// required by MoveFileEx(REPLACE_EXISTING).
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = windows.CloseHandle(handle)
		}
	}()
	called := false
	_, err = store.Transact(ctx, 0, actor(t), func(w ports.Writer) error {
		called = true
		return w.CreateAccount(account(t))
	})
	if !called || !codeIs(err, identity.StorageIntegrityUnverified) || sealed.Load() != 1 {
		t.Fatal("locked witness did not seal the committed generation", called, sealed.Load(), err)
	}
	var revision int
	if err = store.db.QueryRow("SELECT committed_revision FROM settings WHERE singleton=1").Scan(&revision); err != nil || revision != 1 {
		t.Fatal("fault did not reach the post-commit replacement", revision, err)
	}
	witness, err := readWitness(path + witnessSuffix)
	if err != nil || witness.Revision != 0 {
		t.Fatal("locked target witness changed", witness.Revision, err)
	}
	if _, err = os.Lstat(path + pendingSuffix); err != nil {
		t.Fatal("failed replacement did not retain the synchronized staging file", err)
	}
	if err = windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	closed = true
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, openErr := Open(ctx, path, options(t)); reopened != nil || !codeIs(openErr, identity.StorageIntegrityUnverified) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatal("pending replacement reopened writable", openErr)
	}
}
