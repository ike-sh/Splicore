package transport

import (
	"errors"

	"golang.org/x/sys/windows"
)

func platformAbsent(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
}
