// Package sniff inspects bounded stream prefixes for routing metadata only.
package sniff

import (
	"encoding/binary"
	"errors"
	"io"
	"time"

	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
)

const (
	MaxBytes       = 64 << 10
	MaxClientHello = 32 << 10 // includes the four-byte handshake header
	MaxRecord      = 16 << 10
	MaxRecords     = 128
	Timeout        = 2 * time.Second // absolute, never extended by partial progress
)

var (
	ErrMalformed = errors.New("malformed_tls")
	ErrLimit     = errors.New("sniff_limit")
	ErrNoName    = errors.New("no_visible_sni")
)

type Metadata struct {
	Protocol string
	Domain   string
}

// TLS reads complete handshake records until one complete ClientHello is
// available. The caller owns deadlines/cancellation. Prefix contains every byte
// read, including any bytes after ClientHello in its final record, for replay.
// Record framing and ClientHello/SNI vectors follow RFC 8446 and RFC 6066.
func TLS(r io.Reader) (metadata Metadata, prefix []byte, err error) {
	hello := make([]byte, 0, 2048)
	prefix = make([]byte, 0, 2048)
	want := 0
	for range MaxRecords {
		var header [5]byte
		if len(prefix)+len(header) > MaxBytes {
			return Metadata{}, prefix, ErrLimit
		}
		n, e := io.ReadFull(r, header[:])
		prefix = append(prefix, header[:n]...)
		if e != nil {
			return Metadata{}, prefix, e
		}
		if header[0] != 22 || header[1] != 3 || header[2] < 1 || header[2] > 3 {
			return Metadata{}, prefix, ErrMalformed
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if size > MaxRecord || len(prefix)+size > MaxBytes {
			return Metadata{}, prefix, ErrLimit
		}
		if size == 0 {
			return Metadata{}, prefix, ErrMalformed
		}
		start := len(prefix)
		prefix = append(prefix, make([]byte, size)...)
		n, e = io.ReadFull(r, prefix[start:])
		prefix = prefix[:start+n]
		if e != nil {
			return Metadata{}, prefix, e
		}
		payload := prefix[start:]
		// Inspect the advertised handshake length before accepting its body.
		if len(hello) < 4 {
			take := min(4-len(hello), len(payload))
			hello = append(hello, payload[:take]...)
			payload = payload[take:]
			if hello[0] != 1 {
				return Metadata{}, prefix, ErrMalformed
			}
			if len(hello) == 4 {
				want = 4 + (int(hello[1]) << 16) + (int(hello[2]) << 8) + int(hello[3])
				if want > MaxClientHello {
					return Metadata{}, prefix, ErrLimit
				}
			}
		}
		if want > 0 {
			hello = append(hello, payload[:min(len(payload), want-len(hello))]...)
			if len(hello) == want {
				name, e := clientHelloName(hello[4:])
				if e != nil {
					return Metadata{}, prefix, e
				}
				return Metadata{Protocol: "tls", Domain: name}, prefix, nil
			}
		}
	}
	return Metadata{}, prefix, ErrLimit
}

type cursor []byte

func (c *cursor) take(n int) ([]byte, bool) {
	if n < 0 || n > len(*c) {
		return nil, false
	}
	b := (*c)[:n]
	*c = (*c)[n:]
	return b, true
}

func (c *cursor) vector(width int) (cursor, bool) {
	b, ok := c.take(width)
	if !ok {
		return nil, false
	}
	n := int(b[0])
	if width == 2 {
		n = n<<8 | int(b[1])
	}
	v, ok := c.take(n)
	return cursor(v), ok
}

func clientHelloName(b []byte) (string, error) {
	c := cursor(b)
	fixed, ok := c.take(34)
	if !ok || fixed[0] != 3 || fixed[1] != 3 {
		return "", ErrMalformed
	}
	session, ok := c.vector(1)
	if !ok || len(session) > 32 {
		return "", ErrMalformed
	}
	ciphers, ok := c.vector(2)
	if !ok || len(ciphers) == 0 || len(ciphers)%2 != 0 {
		return "", ErrMalformed
	}
	compression, ok := c.vector(1)
	if !ok || len(compression) != 1 || compression[0] != 0 {
		return "", ErrMalformed
	}
	if len(c) == 0 {
		return "", ErrNoName
	}
	extensions, ok := c.vector(2)
	if !ok || len(c) != 0 {
		return "", ErrMalformed
	}
	// Fixed-size bitset bounds duplicate-extension detection independently of input.
	var seen [1024]uint64
	name := ""
	for len(extensions) > 0 {
		kind, ok := extensions.take(2)
		if !ok {
			return "", ErrMalformed
		}
		id := binary.BigEndian.Uint16(kind)
		mask := uint64(1) << (id % 64)
		if seen[id/64]&mask != 0 {
			return "", ErrMalformed
		}
		seen[id/64] |= mask
		value, ok := extensions.vector(2)
		if !ok {
			return "", ErrMalformed
		}
		if id != 0 {
			continue
		}
		list, ok := value.vector(2)
		if !ok || len(value) != 0 || len(list) == 0 {
			return "", ErrMalformed
		}
		// Only one DNS host_name is supported. Unknown/duplicate name types or
		// multiple entries are ambiguous for this routing boundary and fail closed.
		typ, ok := list.take(1)
		if !ok || typ[0] != 0 {
			return "", ErrMalformed
		}
		host, ok := list.vector(2)
		if !ok || len(list) != 0 {
			return "", ErrMalformed
		}
		var e error
		name, e = P.Domain(string(host))
		if e != nil {
			return "", ErrMalformed
		}
	}
	if name == "" {
		return "", ErrNoName
	}
	return name, nil
}
