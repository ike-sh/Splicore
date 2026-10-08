// Package socks preserves the existing internal helper API. All wire framing is
// delegated to the canonical socks5 package.
package socks

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"io"
	"net"
)

const (
	Connect            = socks5.Connect
	UDPAssociate       = socks5.UDPAssociate
	Succeeded          = socks5.Succeeded
	Failure            = socks5.Failure
	NotAllowed         = socks5.NotAllowed
	UnsupportedCommand = socks5.UnsupportedCommand
	UnsupportedAddress = socks5.UnsupportedAddress
)

var ErrHandshake = socks5.ErrHandshake

func AcceptAuth(r io.Reader, w io.Writer) error              { return socks5.AcceptAuth(r, w) }
func ReadCommand(r io.Reader) (byte, access.Endpoint, error) { return socks5.ReadCommand(r) }
func Respond(w io.Writer, code byte, a net.Addr) error       { return socks5.Respond(w, code, a) }
func ErrorReply(e error) byte                                { return socks5.ErrorReply(e) }
func Handshake(c net.Conn, cmd byte, e access.Endpoint) (access.Endpoint, error) {
	return socks5.Handshake(c, cmd, e)
}
