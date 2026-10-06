package hostnetwork

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"golang.org/x/sys/unix"
)

func privateFile(i os.FileInfo) error {
	if st, ok := i.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) || i.Mode().Perm()&0077 != 0 {
		return identity.Err(identity.Invalid, "network recovery file permissions or owner invalid")
	}
	return nil
}
func privatePath(string) error { return nil }
func privateDirectory(path string) error {
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, part)
		i, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err = os.Mkdir(current, 0700); err != nil {
				return err
			}
			continue
		}
		if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return identity.Err(identity.Invalid, "unsafe network recovery directory")
		}
	}
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return privateFile(i)
}
func lockDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(filepath.Join(path, ".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "network-owner-lock")
	i, err := f.Stat()
	if err == nil {
		err = privateFile(i)
	}
	if err == nil && !i.Mode().IsRegular() {
		err = identity.Err(identity.Invalid, "unsafe network recovery lock")
	}
	if err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, identity.Err(identity.Unavailable, "network recovery directory is not exclusively owned")
	}
	return f, nil
}
func replaceFile(from, to string) error { return os.Rename(from, to) }
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
