//go:build !windows

package native

import (
	"errors"
	"syscall"
)

func addressInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }

func snellInvalidListenAddress(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EINVAL)
}
