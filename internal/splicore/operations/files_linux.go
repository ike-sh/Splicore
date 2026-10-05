package operations

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func PrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("private path must be absolute and clean")
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, part)
		i, err := os.Lstat(current)
		if os.IsNotExist(err) {
			break
		}
		if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe private path")
		}
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return fmt.Errorf("private path must not contain symlinks")
	}
	i, err := os.Lstat(path)
	if err != nil || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private directory permissions invalid")
	}
	if s, ok := i.Sys().(*syscall.Stat_t); !ok || s.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private directory owner invalid")
	}
	return nil
}

func recordLock(dir string) (*os.File, error) {
	fd, err := unix.Open(filepath.Join(dir, ".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "record-lock")
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || i.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, fmt.Errorf("unsafe record lock")
	}
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
