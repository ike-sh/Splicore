//go:build !windows

package tlsconfig

import (
	"os"
	"syscall"
)

func ownedTLSFile(i os.FileInfo) bool {
	v, ok := i.Sys().(*syscall.Stat_t)
	return ok && int(v.Uid) == os.Geteuid()
}
