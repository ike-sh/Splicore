package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

const MaxQUICProxyPayload = 65000

// QUICRaw identifies the exact raw/protected demultiplexer observed in the
// official v5.0.1 server. A raw packet is accepted only in an authenticated flow.
func QUICRaw(p []byte) bool { return len(p) > 0 && p[0]&0x40 != 0 }

// QUICInitial is a conservative positive selector for the v1/v2 Initial forms.
// It never uses the UDP destination port. Short headers require an existing flow.
// Surge's private client classifier is not specified by the server distribution.
func QUICInitial(p []byte) bool {
	if len(p) < 1200 || p[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(p[1:5])
	if version == 1 && p[0]&0x30 != 0 || version == 0x6b3343cf && p[0]&0x30 != 0x10 || version != 1 && version != 0x6b3343cf {
		return false
	}
	p = p[5:]
	for range 2 {
		if len(p) == 0 || int(p[0]) > 20 || len(p) < 1+int(p[0]) {
			return false
		}
		p = p[1+int(p[0]):]
	}
	token, n, ok := quicVarint(p)
	if !ok || token > uint64(len(p)-n) {
		return false
	}
	p = p[n+int(token):]
	length, n, ok := quicVarint(p)
	return ok && length >= 17 && length <= uint64(len(p)-n)
}

func quicVarint(p []byte) (uint64, int, bool) {
	if len(p) == 0 {
		return 0, 0, false
	}
	n := 1 << uint(p[0]>>6)
	if len(p) < n {
		return 0, 0, false
	}
	v := uint64(p[0] & 63)
	for _, b := range p[1:n] {
		v = v<<8 | uint64(b)
	}
	return v, n, true
}

// ProtectQUIC uses the existing v4 record cryptography, independently salted per
// UDP packet. The fixed bit is cleared in the random salt before deriving keys.
// The protected plaintext is version | clientID length/data | host length/data |
// big-endian port | original UDP payload, with no TCP command byte.
func ProtectQUIC(k *Key, dst access.Endpoint, p []byte) ([]byte, error) {
	if k == nil || k.version != 5 || dst.Validate() != nil || len(dst.Host) > 255 || len(p) == 0 || len(p) > MaxQUICProxyPayload {
		return nil, ErrFrame
	}
	plain := append([]byte{1, 0, byte(len(dst.Host))}, dst.Host...)
	plain = binary.BigEndian.AppendUint16(plain, dst.Port)
	plain = append(plain, p...)
	salt := make([]byte, 16)
	if _, e := io.ReadFull(rand.Reader, salt); e != nil {
		return nil, e
	}
	salt[0] &= ^byte(0x40)
	state := cryptoState{}
	if e := state.initialize(k, salt); e != nil {
		return nil, e
	}
	head := []byte{4, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(head[5:], uint16(len(plain)))
	out := append(salt, state.aead.Seal(nil, state.nonce[:], head, nil)...)
	if e := state.advance(); e != nil {
		return nil, e
	}
	return append(out, state.aead.Seal(nil, state.nonce[:], plain, nil)...), nil
}

func UnprotectQUIC(k *Key, p []byte) (access.Endpoint, []byte, error) {
	if k == nil || k.version != 5 || len(p) < 55 || len(p) > 65507 || QUICRaw(p) {
		return access.Endpoint{}, nil, ErrFrame
	}
	r := bytes.NewReader(p)
	d := NewDecoder(r, k)
	plain := make([]byte, 0, len(p))
	for r.Len() > 0 {
		b, e := d.Next()
		if e != nil {
			return access.Endpoint{}, nil, e
		}
		if len(plain)+len(b) > 65507 {
			return access.Endpoint{}, nil, ErrFrame
		}
		plain = append(plain, b...)
	}
	return decodeQUICControl(plain)
}

func decodeQUICControl(p []byte) (access.Endpoint, []byte, error) {
	if len(p) < 3 || p[0] != 1 || len(p) < 3+int(p[1]) {
		return access.Endpoint{}, nil, ErrFrame
	}
	p = p[2+int(p[1]):]
	n := int(p[0])
	if len(p) < 3+n {
		return access.Endpoint{}, nil, ErrFrame
	}
	dst := access.Endpoint{Host: canonicalHost(string(p[1 : 1+n])), Port: binary.BigEndian.Uint16(p[1+n : 3+n])}
	payload := p[3+n:]
	if dst.Validate() != nil || len(payload) == 0 || len(payload) > MaxQUICProxyPayload {
		return access.Endpoint{}, nil, ErrFrame
	}
	return dst, payload, nil
}
