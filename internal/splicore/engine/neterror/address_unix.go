//go:build !windows

package neterror

import (
	"errors"
	"syscall"
)

func AddressInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
