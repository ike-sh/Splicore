package tlsconfig

import (
	"github.com/ike-sh/Splicore/internal/splicore/privatefs"
	"path/filepath"
)

func platformTLS(path string, private bool) error {
	if !private {
		return nil
	}
	if err := privatefs.CheckDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return privatefs.CheckFile(path)
}
