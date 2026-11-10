package secretvault

import (
	"github.com/ike-sh/Splicore/internal/splicore/privatefs"
	"golang.org/x/sys/windows"
	"os"
)

func prepareKeyDirectory(path string) error { return privatefs.EnsureDirectory(path) }
func checkKeyPath(path string, directory bool) error {
	if directory {
		return privatefs.CheckDirectory(path)
	}
	return privatefs.CheckFile(path)
}

// Path-based owner/DACL validation is performed before and after opening the key.
func keyOwner(os.FileInfo) error { return nil }

func checkOpenedKey(f *os.File) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return privatefs.CheckFileDescriptor(sd)
}
