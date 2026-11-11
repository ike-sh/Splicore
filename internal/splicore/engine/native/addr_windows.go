package native

import (
	"errors"
	"golang.org/x/sys/windows"
)

func addressInUse(err error) bool { return errors.Is(err, windows.WSAEADDRINUSE) }

func snellInvalidListenAddress(err error) bool {
	return errors.Is(err, windows.WSAEADDRNOTAVAIL) || errors.Is(err, windows.WSAEAFNOSUPPORT) || errors.Is(err, windows.WSAEINVAL)
}
