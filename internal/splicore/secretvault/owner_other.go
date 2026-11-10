//go:build !linux && !windows

package secretvault

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"os"
)

func prepareKeyDirectory(string) error {
	return identity.Err(identity.NotImplemented, "production key provisioning requires supported permissions")
}
func checkKeyPath(string, bool) error {
	return identity.Err(identity.NotImplemented, "production key files require supported permissions")
}

func keyOwner(os.FileInfo) error {
	return identity.Err(identity.NotImplemented, "production key files require Linux permission checks")
}
func checkOpenedKey(*os.File) error {
	return identity.Err(identity.NotImplemented, "production key files require supported permissions")
}
