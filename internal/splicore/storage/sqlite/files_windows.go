package sqlite

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"

	"golang.org/x/sys/windows"
)

// Windows Foundation is a development target. Production DACL provisioning is deferred.
func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return identity.Err(identity.Unavailable, "cannot create state directory")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.EqualFold(resolved, filepath.Clean(path)) {
		return identity.Err(identity.Invalid, "state directory must not use reparse points")
	}
	return nil
}

func safeFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return identity.Err(identity.Invalid, "unsafe database file type")
	}
	return nil
}

func lockFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}

func unlockFile(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{})
}
