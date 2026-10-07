package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"net/netip"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

const (
	TCP           byte = 1
	UDP           byte = 2
	AESGCM        byte = 3
	ChaCha        byte = 4
	None          byte = 5
	ChunkStream   byte = 1
	LengthMask    byte = 4
	GlobalPadding byte = 8
	MaxHeader          = 316
)

type Request struct {
	Destination                access.Endpoint
	Command, Security, Options byte
	key, iv                    [16]byte
	response                   byte
}

func (Request) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("VMessRequest{[REDACTED]}")) }
func (r Request) Validate() error {
	if r.Destination.Validate() != nil || r.Command != TCP && r.Command != UDP || r.Security != AESGCM && r.Security != ChaCha && r.Security != None || r.Options & ^byte(ChunkStream|LengthMask|GlobalPadding) != 0 {
		return ErrFrame
	}
	if r.Options&ChunkStream == 0 && (r.Security != None || r.Command != TCP || r.Options != 0) {
		return ErrFrame
	}
	if r.Options&GlobalPadding != 0 && (r.Options&LengthMask == 0 || r.Security == None) {
		return ErrFrame
	}
	return nil
}
func NewRequest(dst access.Endpoint, command, security, options byte, random io.Reader) (Request, error) {
	r := Request{Destination: dst, Command: command, Security: security, Options: options}
	if r.Validate() != nil {
		return r, ErrFrame
	}
	if err := randomBytes(random, r.key[:]); err != nil {
		return r, err
	}
	if err := randomBytes(random, r.iv[:]); err != nil {
		return r, err
	}
	var v [1]byte
	if err := randomBytes(random, v[:]); err != nil {
		return r, err
	}
	r.response = v[0]
	return r, nil
}
func (r Request) Material(response bool) (key, iv [16]byte) {
	if !response {
		return r.key, r.iv
	}
	k := sha256.Sum256(r.key[:])
	v := sha256.Sum256(r.iv[:])
	copy(key[:], k[:16])
	copy(iv[:], v[:16])
	return
}
func checksum(b []byte) uint32 { h := fnv.New32a(); _, _ = h.Write(b); return h.Sum32() }
func (r Request) encode(random io.Reader) ([]byte, error) {
	if r.Validate() != nil {
		return nil, ErrFrame
	}
	var selection [1]byte
	if err := randomBytes(random, selection[:]); err != nil {
		return nil, err
	}
	pad := int(selection[0] & 15)
	b := []byte{1}
	b = append(b, r.iv[:]...)
	b = append(b, r.key[:]...)
	b = append(b, r.response, r.Options, byte(pad<<4)|r.Security, 0, r.Command, byte(r.Destination.Port>>8), byte(r.Destination.Port))
	if ip, err := netip.ParseAddr(r.Destination.Host); err == nil {
		if ip.Is4() {
			v := ip.As4()
			b = append(b, 1)
			b = append(b, v[:]...)
		} else {
			v := ip.As16()
			b = append(b, 3)
			b = append(b, v[:]...)
		}
	} else {
		if len(r.Destination.Host) > 255 {
			return nil, ErrFrame
		}
		b = append(b, 2, byte(len(r.Destination.Host)))
		b = append(b, r.Destination.Host...)
	}
	padding := make([]byte, pad)
	if err := randomBytes(random, padding); err != nil {
		return nil, err
	}
	b = append(b, padding...)
	b = binary.BigEndian.AppendUint32(b, checksum(b))
	return b, nil
}
func DecodeRequest(b []byte) (Request, error) {
	var r Request
	if len(b) < 47 || len(b) > MaxHeader || b[0] != 1 || b[36] != 0 || binary.BigEndian.Uint32(b[len(b)-4:]) != checksum(b[:len(b)-4]) {
		return r, ErrFrame
	}
	copy(r.iv[:], b[1:17])
	copy(r.key[:], b[17:33])
	r.response = b[33]
	r.Options = b[34]
	r.Security = b[35] & 15
	r.Command = b[37]
	r.Destination.Port = binary.BigEndian.Uint16(b[38:40])
	pad := int(b[35] >> 4)
	body := b[41 : len(b)-4]
	var addressLen int
	switch b[40] {
	case 1:
		addressLen = 4
		if len(body) < 4 {
			return r, ErrFrame
		}
		r.Destination.Host = netip.AddrFrom4([4]byte(body[:4])).String()
	case 3:
		addressLen = 16
		if len(body) < 16 {
			return r, ErrFrame
		}
		r.Destination.Host = netip.AddrFrom16([16]byte(body[:16])).String()
	case 2:
		if len(body) == 0 || body[0] == 0 {
			return r, ErrFrame
		}
		addressLen = 1 + int(body[0])
		if len(body) < addressLen {
			return r, ErrFrame
		}
		r.Destination.Host = string(body[1:addressLen])
	default:
		return r, ErrFrame
	}
	if len(body) != addressLen+pad || r.Validate() != nil {
		return Request{}, ErrFrame
	}
	return r, nil
}
func EncodeRequest(key Key, r Request, now time.Time, random io.Reader) ([]byte, error) {
	plain, err := r.encode(random)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	auth, err := AuthID(key, now, random)
	if err != nil {
		return nil, err
	}
	var nonce [8]byte
	if err := randomBytes(random, nonce[:]); err != nil {
		return nil, err
	}
	lengthCipher, lengthNonce := headerCipher(key, "VMess Header AEAD Key_Length", auth, nonce)
	payloadCipher, payloadNonce := headerCipher(key, "VMess Header AEAD Key", auth, nonce)
	out := append([]byte{}, auth[:]...)
	out = lengthCipher.Seal(out, lengthNonce[:], binary.BigEndian.AppendUint16(nil, uint16(len(plain))), auth[:])
	out = append(out, nonce[:]...)
	out = payloadCipher.Seal(out, payloadNonce[:], plain, auth[:])
	return out, nil
}

// OpenHeader reads only the authenticated header, leaving coalesced data intact.
func OpenHeader(reader io.Reader, key Key, auth [16]byte) ([]byte, error) {
	var prefix [26]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	var nonce [8]byte
	copy(nonce[:], prefix[18:])
	lc, ln := headerCipher(key, "VMess Header AEAD Key_Length", auth, nonce)
	length, err := lc.Open(nil, ln[:], prefix[:18], auth[:])
	if err != nil {
		return nil, ErrAuth
	}
	n := int(binary.BigEndian.Uint16(length))
	if n < 47 || n > MaxHeader {
		return nil, ErrFrame
	}
	encrypted := make([]byte, n+16)
	if _, err := io.ReadFull(reader, encrypted); err != nil {
		return nil, err
	}
	pc, pn := headerCipher(key, "VMess Header AEAD Key", auth, nonce)
	plain, err := pc.Open(nil, pn[:], encrypted, auth[:])
	if err != nil {
		return nil, ErrAuth
	}
	return plain, nil
}
func ReadRequest(reader io.Reader, users []User, replay *Replay, now time.Time) (Request, string, error) {
	return ReadRequestWithClock(reader, users, replay, func() time.Time { return now })
}

// ReadRequestWithClock samples the injected validation clock after the complete
// AuthID read. Later header reads retain that authentication decision; the
// independent handshake deadline and atomic replay admission still apply.
func ReadRequestWithClock(reader io.Reader, users []User, replay *Replay, clock func() time.Time) (Request, string, error) {
	var auth [16]byte
	if _, err := io.ReadFull(reader, auth[:]); err != nil {
		return Request{}, "", err
	}
	now := clock()
	u, timestamp, err := match(auth, users, now)
	if err != nil {
		return Request{}, "", ErrAuth
	}
	plain, err := OpenHeader(reader, u.key, auth)
	if err != nil {
		return Request{}, "", err
	}
	defer clear(plain)
	r, err := DecodeRequest(plain)
	if err != nil {
		return Request{}, "", err
	}
	responseKey, responseIV := r.Material(true)
	tokens := [][32]byte{replayToken(1, u.key[:], auth[:]), replayToken(2, r.key[:], r.iv[2:12]), replayToken(2, responseKey[:], responseIV[2:12])}
	if err := replay.reserve(now.Unix(), timestamp, tokens); err != nil {
		return Request{}, "", ErrAuth
	}
	return r, u.ID, nil
}
func responseCipher(r Request, keyLabel, ivLabel string) (cipherKey [16]byte, nonce [12]byte) {
	key, iv := r.Material(true)
	k := KDF(key[:], []byte(keyLabel))
	n := KDF(iv[:], []byte(ivLabel))
	copy(cipherKey[:], k[:16])
	copy(nonce[:], n[:12])
	return
}
func EncodeResponse(r Request) []byte {
	k, n := responseCipher(r, "AEAD Resp Header Len Key", "AEAD Resp Header Len IV")
	out := gcm(k[:]).Seal(nil, n[:], []byte{0, 4}, nil)
	k, n = responseCipher(r, "AEAD Resp Header Key", "AEAD Resp Header IV")
	return gcm(k[:]).Seal(out, n[:], []byte{r.response, 0, 0, 0}, nil)
}
func ReadResponse(reader io.Reader, r Request) error {
	var length [18]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return err
	}
	k, n := responseCipher(r, "AEAD Resp Header Len Key", "AEAD Resp Header Len IV")
	b, err := gcm(k[:]).Open(nil, n[:], length[:], nil)
	if err != nil || !bytes.Equal(b, []byte{0, 4}) {
		return ErrAuth
	}
	var payload [20]byte
	if _, err := io.ReadFull(reader, payload[:]); err != nil {
		return err
	}
	k, n = responseCipher(r, "AEAD Resp Header Key", "AEAD Resp Header IV")
	b, err = gcm(k[:]).Open(nil, n[:], payload[:], nil)
	// Xray sends zero response options; current sing-vmess echoes the exact
	// request options. Accept that declaration without enabling stream reuse.
	// Commands/extensions and any other option declaration remain unsupported.
	if err != nil || len(b) != 4 || b[0] != r.response || b[2] != 0 || b[3] != 0 || b[1] != 0 && b[1] != r.Options {
		return ErrAuth
	}
	return nil
}
