//go:build !windows

package native

import (
	"errors"
	"syscall"
)

func addressInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
