//go:build !linux

package secretvault

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"os"
)

func keyOwner(os.FileInfo) error {
	return identity.Err(identity.NotImplemented, "production key files require Linux permission checks")
}
