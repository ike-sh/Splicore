//go:build windows

package native

import "os"

func ownedTLSFile(os.FileInfo) bool { return false }
