//go:build !windows

package testkit

import "os"

func privateTLSDirectory(path string) error { return os.Mkdir(path, 0700) }
