package secretvault

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"os"
	"syscall"
)

func prepareKeyDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return identity.Err(identity.Unavailable, "key directory unavailable")
	}
	return checkKeyDirectory(path)
}
func checkKeyPath(string, bool) error { return nil }
func checkOpenedKey(*os.File) error   { return nil }

func keyOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return identity.Err(identity.Invalid, "key must be owned by current principal")
	}
	return nil
}
