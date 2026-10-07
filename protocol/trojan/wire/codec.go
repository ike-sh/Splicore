// Package wire implements standard Trojan application framing after TLS.
package wire

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
)

const (
	Connect    byte = 1
	Associate  byte = 3
	MaxPayload      = 65535
)

var ErrRequest = errors.New("invalid Trojan request")
var ErrFrame = errors.New("invalid Trojan UDP frame")

// Key is secret-equivalent immutable runtime material, never diagnostic data.
type Key [56]byte

func (Key) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[REDACTED]")) }
func Derive(password secret.Value) (key Key) {
	sum := sha256.Sum224([]byte(password.Reveal()))
	hex.Encode(key[:], sum[:])
	return
}

type User struct {
	ID  string
	Key Key
}

// Match scans the complete fixed-size generation without a user-dependent exit.
func Match(key Key, users []User) (string, bool) {
	index, matched := -1, 0
	for i := range users {
		equal := subtle.ConstantTimeCompare(key[:], users[i].Key[:])
		index = subtle.ConstantTimeSelect(equal, i, index)
		matched |= equal
	}
	if matched != 1 {
		return "", false
	}
	return users[index].ID, true
}

type Request struct {
	Key         Key
	Command     byte
	Destination access.Endpoint
}

func (Request) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("TrojanRequest{[REDACTED]}")) }

func delimiter(r io.Reader) bool {
	var b [2]byte
	_, err := io.ReadFull(r, b[:])
	return err == nil && b == [2]byte{'\r', '\n'}
}

func ReadRequest(r io.Reader) (Request, error) {
	var v Request
	if _, err := io.ReadFull(r, v.Key[:]); err != nil {
		return Request{}, ErrRequest
	}
	for _, b := range v.Key {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return Request{}, ErrRequest
		}
	}
	if !delimiter(r) {
		return Request{}, ErrRequest
	}
	var command [1]byte
	if _, err := io.ReadFull(r, command[:]); err != nil || command[0] != Connect && command[0] != Associate {
		return Request{}, ErrRequest
	}
	dst, err := address.ReadSOCKS(r)
	if err != nil || command[0] == Connect && dst.Port == 0 || !delimiter(r) {
		return Request{}, ErrRequest
	}
	v.Command, v.Destination = command[0], dst
	return v, nil
}

// EncodeRequest produces independent bounded header storage, without consuming
// payload bytes that follow the request on the same application stream.
func EncodeRequest(key Key, command byte, dst access.Endpoint) ([]byte, error) {
	if command != Connect && command != Associate || command == Connect && dst.Port == 0 {
		return nil, ErrRequest
	}
	addr, err := address.MarshalSOCKS(dst)
	if err != nil {
		return nil, ErrRequest
	}
	b := make([]byte, 0, len(key)+len(addr)+5)
	b = append(b, key[:]...)
	b = append(b, '\r', '\n', command)
	b = append(b, addr...)
	return append(b, '\r', '\n'), nil
}

func EncodePacket(payload []byte, dst access.Endpoint) ([]byte, error) {
	if len(payload) > MaxPayload || dst.Validate() != nil {
		return nil, ErrFrame
	}
	addr, err := address.MarshalSOCKS(dst)
	if err != nil {
		return nil, ErrFrame
	}
	b := make([]byte, 0, len(addr)+4+len(payload))
	b = append(b, addr...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	b = append(b, '\r', '\n')
	return append(b, payload...), nil
}

func ReadPacket(r io.Reader) ([]byte, access.Endpoint, error) {
	dst, err := address.ReadSOCKS(r)
	if err != nil || dst.Validate() != nil {
		return nil, access.Endpoint{}, ErrFrame
	}
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil || !delimiter(r) {
		return nil, access.Endpoint{}, ErrFrame
	}
	b := make([]byte, int(binary.BigEndian.Uint16(length[:])))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, access.Endpoint{}, ErrFrame
	}
	return b, dst, nil
}
