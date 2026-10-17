package streamtransport

import (
	"net"
	"time"
)

// BeginAdmission explicitly separates transport delivery from protocol work
// when the transport supports it. Other transports retain an absolute deadline.
// The returned connection becomes an ordinary net.Conn after finish succeeds.
// The caller must close the connection on failure and honor its context.
// Construct authentication wrappers before calling this helper so an ordinary
// absolute deadline reaches every layer that owns deadline state.
func BeginAdmission(c net.Conn, budget time.Duration) (net.Conn, func() error) {
	if v, ok := c.(interface {
		BeginAdmission(time.Duration) (net.Conn, func() error)
	}); ok {
		return v.BeginAdmission(budget)
	}
	_ = c.SetDeadline(time.Now().Add(budget))
	return c, func() error { return c.SetDeadline(time.Time{}) }
}
