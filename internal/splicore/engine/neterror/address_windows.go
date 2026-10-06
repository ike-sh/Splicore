package neterror

import (
	"errors"
	"golang.org/x/sys/windows"
)

func AddressInUse(err error) bool { return errors.Is(err, windows.WSAEADDRINUSE) }
