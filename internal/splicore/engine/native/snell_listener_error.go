package native

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

// Keep the safe domain error and the original net/syscall error independently
// inspectable. API and CLI boundaries continue to select allowlisted messages.
func snellListenError(message string, cause error) error {
	code := identity.Unavailable
	var address *net.AddrError
	switch {
	case addressInUse(cause):
		code, message = identity.PortConflict, "Snell listener port is already in use"
	case errors.Is(cause, os.ErrPermission):
		message = "Snell listener permission denied"
	case errors.As(cause, &address) || snellInvalidListenAddress(cause):
		code, message = identity.Invalid, "invalid Snell listener address"
	case errors.Is(cause, net.ErrClosed):
		message = "Snell listener is closed"
	}
	return fmt.Errorf("%w: %w", identity.Err(code, message), cause)
}
