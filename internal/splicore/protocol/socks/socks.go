// Package socks implements Splicore's existing local SOCKS5 ingress contract:
// no authentication, CONNECT and UDP ASSOCIATE (RFC 1928). It owns no sockets.
package socks

import (
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
)

const (
	Connect            byte = 1
	UDPAssociate       byte = 3
	Succeeded          byte = 0
	Failure            byte = 1
	NotAllowed         byte = 2
	UnsupportedCommand byte = 7
	UnsupportedAddress byte = 8
)

var ErrHandshake = errors.New("invalid SOCKS5 handshake")

func write(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}

// AcceptAuth consumes only the greeting, leaving pipelined requests untouched.
func AcceptAuth(r io.Reader, w io.Writer) error {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	if h[0] != 5 || h[1] == 0 {
		return ErrHandshake
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}
	method := byte(255)
	for _, m := range methods {
		if m == 0 {
			method = 0
		}
	}
	if err := write(w, []byte{5, method}); err != nil {
		return err
	}
	if method != 0 {
		return ErrHandshake
	}
	return nil
}

func ReadCommand(r io.Reader) (byte, access.Endpoint, error) {
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, access.Endpoint{}, err
	}
	if h[0] != 5 || h[2] != 0 {
		return 0, access.Endpoint{}, ErrHandshake
	}
	e, err := address.ReadSOCKS(r)
	return h[1], e, err
}

func Respond(w io.Writer, code byte, bind net.Addr) error {
	e, err := netaddr.From(bind)
	if err != nil {
		return err
	}
	b, err := address.MarshalSOCKS(e)
	if err != nil {
		return err
	}
	return write(w, append([]byte{5, code, 0}, b...))
}

func ErrorReply(err error) byte {
	var op *net.OpError
	if errors.As(err, &op) && op.Timeout() {
		return 6
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return 5
	case errors.Is(err, syscall.ENETUNREACH):
		return 3
	case errors.Is(err, syscall.EHOSTUNREACH):
		return 4
	case errors.Is(err, syscall.EACCES):
		return NotAllowed
	}
	return Failure
}

// Handshake is the localhost fixture/client boundary for the same limited
// contract. It returns the server's semantic bind endpoint, including port zero.
func Handshake(c net.Conn, command byte, target access.Endpoint) (access.Endpoint, error) {
	if err := write(c, []byte{5, 1, 0}); err != nil {
		return access.Endpoint{}, err
	}
	var auth [2]byte
	if _, err := io.ReadFull(c, auth[:]); err != nil {
		return access.Endpoint{}, err
	}
	if auth != [2]byte{5, 0} {
		return access.Endpoint{}, ErrHandshake
	}
	b, err := address.MarshalSOCKS(target)
	if err != nil {
		return access.Endpoint{}, err
	}
	if err = write(c, append([]byte{5, command, 0}, b...)); err != nil {
		return access.Endpoint{}, err
	}
	code, bind, err := ReadCommand(c)
	if err != nil {
		return access.Endpoint{}, err
	}
	if code != Succeeded {
		return bind, ErrHandshake
	}
	return bind, nil
}
