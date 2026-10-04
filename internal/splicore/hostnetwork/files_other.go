//go:build !linux && !windows

package hostnetwork

import "os"

func privatePath(string) error { return os.ErrInvalid }

func privateFile(os.FileInfo) error          { return os.ErrInvalid }
func privateDirectory(string) error          { return os.ErrInvalid }
func lockDirectory(string) (*os.File, error) { return nil, os.ErrInvalid }
func replaceFile(string, string) error       { return os.ErrInvalid }
func syncDirectory(string) error             { return os.ErrInvalid }
