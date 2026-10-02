//go:build windows

package tlsconfig

import "os"

func ownedTLSFile(os.FileInfo) bool { return false }
