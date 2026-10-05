package secretvault

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"os"
	"syscall"
)

func keyOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return identity.Err(identity.Invalid, "key must be owned by current principal")
	}
	return nil
}
