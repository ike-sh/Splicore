// Package socks5 owns bounded RFC 1928/1929 framing. It owns no sockets.
package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
	"io"
	"net"
	"syscall"
)

const (
	Connect            byte = 1
	UDPAssociate       byte = 3
	Succeeded          byte = 0
	Failure            byte = 1
	NotAllowed         byte = 2
	UnsupportedCommand byte = 7
	UnsupportedAddress byte = 8
	MaxPacket               = 65507
)

var ErrHandshake = errors.New("invalid SOCKS5 handshake")

type Credentials struct{ Username, Password string }

func (Credentials) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[REDACTED]")) }
func (c Credentials) Validate() error {
	if len(c.Username) < 1 || len(c.Username) > 255 || len(c.Password) < 1 || len(c.Password) > 255 {
		return ErrHandshake
	}
	return nil
}

// WriteFull completes positive short writes synchronously. Any terminal error
// leaves the connection unusable for further framing and belongs to the caller.
func WriteFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func AcceptAuth(r io.Reader, w io.Writer) error { return AcceptAuthWithVerifier(r, w, nil) }
func AcceptAuthWithVerifier(r io.Reader, w io.Writer, verify func(string, string) bool) error {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return e
	}
	if h[0] != 5 || h[1] == 0 {
		return ErrHandshake
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(r, methods); e != nil {
		return e
	}
	want := byte(0)
	if verify != nil {
		want = 2
	}
	method := byte(255)
	for _, v := range methods {
		if v == want {
			method = want
		}
	}
	if e := WriteFull(w, []byte{5, method}); e != nil {
		return e
	}
	if method == 255 {
		return ErrHandshake
	}
	if method == 0 {
		return nil
	}
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return e
	}
	if h[0] != 1 || h[1] == 0 {
		return ErrHandshake
	}
	user := make([]byte, int(h[1]))
	defer clear(user)
	if _, e := io.ReadFull(r, user); e != nil {
		return e
	}
	var size [1]byte
	if _, e := io.ReadFull(r, size[:]); e != nil {
		return e
	}
	if size[0] == 0 {
		return ErrHandshake
	}
	pass := make([]byte, int(size[0]))
	defer clear(pass)
	if _, e := io.ReadFull(r, pass); e != nil {
		return e
	}
	status := byte(1)
	if verify(string(user), string(pass)) {
		status = 0
	}
	if e := WriteFull(w, []byte{1, status}); e != nil {
		return e
	}
	if status != 0 {
		return ErrHandshake
	}
	return nil
}
func ReadCommand(r io.Reader) (byte, access.Endpoint, error) {
	var h [3]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return 0, access.Endpoint{}, e
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
	return WriteFull(w, append([]byte{5, code, 0}, b...))
}
func ErrorReply(err error) byte {
	var dns *net.DNSError
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return 5
	case errors.Is(err, syscall.ENETUNREACH):
		return 3
	case errors.Is(err, syscall.EHOSTUNREACH), errors.As(err, &dns):
		return 4
	case errors.Is(err, syscall.EACCES):
		return NotAllowed
	}
	return Failure
}
func Handshake(c net.Conn, command byte, target access.Endpoint) (access.Endpoint, error) {
	return ClientHandshake(c, command, target, nil)
}
func ClientHandshake(c net.Conn, command byte, target access.Endpoint, cred *Credentials) (access.Endpoint, error) {
	method := byte(0)
	if cred != nil {
		if cred.Validate() != nil {
			return access.Endpoint{}, ErrHandshake
		}
		method = 2
	}
	if e := WriteFull(c, []byte{5, 1, method}); e != nil {
		return access.Endpoint{}, e
	}
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return access.Endpoint{}, e
	}
	if h != [2]byte{5, method} {
		return access.Endpoint{}, ErrHandshake
	}
	if cred != nil {
		b := []byte{1, byte(len(cred.Username))}
		b = append(b, cred.Username...)
		b = append(b, byte(len(cred.Password)))
		b = append(b, cred.Password...)
		err := WriteFull(c, b)
		clear(b)
		if err != nil {
			return access.Endpoint{}, err
		}
		if _, e := io.ReadFull(c, h[:]); e != nil {
			return access.Endpoint{}, e
		}
		if h != [2]byte{1, 0} {
			return access.Endpoint{}, ErrHandshake
		}
	}
	b, e := address.MarshalSOCKS(target)
	if e != nil {
		return access.Endpoint{}, e
	}
	if e = WriteFull(c, append([]byte{5, command, 0}, b...)); e != nil {
		return access.Endpoint{}, e
	}
	code, bind, e := ReadCommand(c)
	if e != nil {
		return access.Endpoint{}, e
	}
	if code != Succeeded {
		return bind, ErrHandshake
	}
	return bind, nil
}
func ParsePacket(b []byte) (access.Endpoint, []byte, error) {
	if len(b) < 4 || len(b) > MaxPacket || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return access.Endpoint{}, nil, ErrHandshake
	}
	r := bytes.NewReader(b[3:])
	e, err := address.ReadSOCKS(r)
	if err != nil || e.Validate() != nil {
		return access.Endpoint{}, nil, ErrHandshake
	}
	return e, b[len(b)-r.Len():], nil
}
func EncodePacket(e access.Endpoint, p []byte) ([]byte, error) {
	if e.Validate() != nil {
		return nil, ErrHandshake
	}
	b, err := address.MarshalSOCKS(e)
	if err != nil {
		return nil, err
	}
	if 3+len(b)+len(p) > MaxPacket {
		return nil, ErrHandshake
	}
	frame := make([]byte, 3, 3+len(b)+len(p))
	frame = append(frame, b...)
	return append(frame, p...), nil
}
