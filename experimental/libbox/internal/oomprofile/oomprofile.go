//go:build darwin || linux || windows

// Package oomprofile writes the profiles used by the inherited libbox recorder.
// Splicore QF-003 replaces the private runtime ABI implementation with public
// runtime/pprof APIs. Files contain standard gzip-compressed pprof protobufs.
package oomprofile

import (
	"fmt"
	"os"
	"runtime/pprof"
)

// WriteFile captures a supported runtime profile. Capture is best effort:
// runtime/pprof allocates memory and does not guarantee success under OOM.
func WriteFile(filePath string, name string) error {
	switch name {
	case "allocs", "block", "goroutine", "heap", "mutex", "threadcreate":
	default:
		return fmt.Errorf("unsupported profile %q", name)
	}
	profile := pprof.Lookup(name)
	if profile == nil {
		return fmt.Errorf("unsupported profile %q", name)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	err = profile.WriteTo(file, 0)
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(filePath)
	}
	return err
}
