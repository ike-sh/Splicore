// Package backend owns Trojan TLS stream and packet lifecycle adapters.
package backend

import (
	"io"
	"net"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/protocol/trojan/wire"
)

// Stream preserves TLS half-close and aborts the raw socket on full shutdown,
// so close_notify cannot strand a Stop behind a peer that stopped reading.
type Stream struct {
	net.Conn
	Raw net.Conn
}

func (s *Stream) Close() error {
	if s.Raw != nil {
		_ = s.Raw.Close()
	}
	return s.Conn.Close()
}
func (s *Stream) CloseWrite() error {
	if c, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return s.Close()
}

// Client authenticates eagerly, also supporting server-first TCP applications.
// A failed/short request write never publishes a reusable connection.
func Client(c net.Conn, key wire.Key, command byte, dst access.Endpoint) error {
	b, err := wire.EncodeRequest(key, command, dst)
	if err != nil {
		return err
	}
	defer clear(b)
	n, err := c.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = c.Close()
		return err
	}
	return nil
}
