//go:build !windows

package sqlite

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"

	"golang.org/x/sys/unix"
)

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return identity.Err(identity.Unavailable, "cannot create private state directory")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return identity.Err(identity.Invalid, "state directory must not use symlinks")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return identity.Err(identity.Invalid, "state directory must have mode 0700")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return identity.Err(identity.Invalid, "state directory must be owned by current principal")
	}
	return nil
}

func safeFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return identity.Err(identity.Invalid, "unsafe database file permissions or type")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return identity.Err(identity.Invalid, "unsafe database file owner")
	}
	return nil
}
func lockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func unlockFile(f *os.File)     { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }

// Root may create a stopped-service backup without changing database ownership.
func maintenanceFile(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return identity.Err(identity.Invalid, "unsafe maintenance path")
	}
	i, err := os.Lstat(path)
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		return identity.Err(identity.Invalid, "unsafe maintenance file")
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || os.Geteuid() != 0 && s.Uid != uint32(os.Geteuid()) {
		return identity.Err(identity.Invalid, "maintenance owner mismatch")
	}
	return nil
}
