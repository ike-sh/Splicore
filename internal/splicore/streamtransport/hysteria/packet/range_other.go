//go:build !linux

package packet

import (
	"errors"
	"net"
)

func installRange(*net.UDPAddr, uint16, uint16) (func() error, error) {
	return nil, errors.New("Hysteria built-in server UDP range requires Linux nftables; use an external UDP redirector on this platform")
}
