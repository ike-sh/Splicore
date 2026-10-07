// Package wire implements modern VMess AEAD from its published wire contracts.
// Reference versions and independent oracle provenance live in the Phase19 report.
// No legacy authentication or external-core runtime is included.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"time"
)

var (
	ErrAuth    = errors.New("VMess authentication failed")
	ErrFrame   = errors.New("invalid or unsupported VMess frame")
	ErrCounter = errors.New("VMess chunk counter exhausted")
)

const SkewSeconds int64 = 120

type Key [16]byte

func (Key) MarshalJSON() ([]byte, error) { return []byte("\"[REDACTED]\""), nil }

func (Key) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("VMessKey{[REDACTED]}")) }

// CommandKey is the protocol-mandated MD5 composition, not a password KDF.
func CommandKey(id [16]byte) Key {
	h := md5.New()
	_, _ = h.Write(id[:])
	_, _ = h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	var k Key
	copy(k[:], h.Sum(nil))
	return k
}

// KDF follows the nested HMAC construction. Each path component is itself an
// HMAC key; the final message is the master key. This is not chained HKDF.
func KDF(key []byte, path ...[]byte) [32]byte {
	factory := func() hash.Hash { return hmac.New(sha256.New, []byte("VMess AEAD KDF")) }
	for _, label := range path {
		parent := factory
		factory = func() hash.Hash { return hmac.New(parent, label) }
	}
	h := factory()
	_, _ = h.Write(key)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func gcm(key []byte) cipher.AEAD {
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	return a
}
func headerCipher(key Key, label string, auth [16]byte, nonce [8]byte) (cipher.AEAD, [12]byte) {
	k := KDF(key[:], []byte(label), auth[:], nonce[:])
	ivLabel := "VMess Header AEAD Nonce"
	if label == "VMess Header AEAD Key_Length" {
		ivLabel = "VMess Header AEAD Nonce_Length"
	}
	iv := KDF(key[:], []byte(ivLabel), auth[:], nonce[:])
	var n [12]byte
	copy(n[:], iv[:12])
	return gcm(k[:16]), n
}
func randomBytes(r io.Reader, b []byte) error {
	if r == nil {
		r = rand.Reader
	}
	_, err := io.ReadFull(r, b)
	return err
}
func ValidTime(timestamp, now int64) bool {
	if timestamp < 0 || now < 0 {
		return false
	}
	if timestamp > now {
		return timestamp-now <= SkewSeconds
	}
	return now-timestamp <= SkewSeconds
}
func AuthID(key Key, now time.Time, r io.Reader) ([16]byte, error) {
	var b, out [16]byte
	if now.Unix() < 0 {
		return out, ErrAuth
	}
	binary.BigEndian.PutUint64(b[:8], uint64(now.Unix()))
	if err := randomBytes(r, b[8:12]); err != nil {
		return out, err
	}
	binary.BigEndian.PutUint32(b[12:], crc32.ChecksumIEEE(b[:12]))
	k := KDF(key[:], []byte("AES Auth ID Encryption"))
	block, _ := aes.NewCipher(k[:16])
	block.Encrypt(out[:], b[:])
	return out, nil
}

// User snapshots its derived AES auth decoder. Candidate work is one AES block
// per configured user, capped at sixteen by the managed runtime.
type User struct {
	ID      string
	key     Key
	decoder cipher.Block
}

func NewUser(id string, key Key) User {
	k := KDF(key[:], []byte("AES Auth ID Encryption"))
	block, _ := aes.NewCipher(k[:16])
	return User{ID: id, key: key, decoder: block}
}
func (User) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("VMessUser{[REDACTED]}")) }
func match(auth [16]byte, users []User, now time.Time) (User, int64, error) {
	var selected User
	var timestamp int64
	matches := 0
	if len(users) > 16 {
		return selected, 0, ErrAuth
	}
	for _, u := range users {
		if u.decoder == nil {
			continue
		}
		var p [16]byte
		u.decoder.Decrypt(p[:], auth[:])
		t := int64(binary.BigEndian.Uint64(p[:8]))
		if binary.BigEndian.Uint32(p[12:]) == crc32.ChecksumIEEE(p[:12]) && ValidTime(t, now.Unix()) {
			selected = u
			timestamp = t
			matches++
		}
		clear(p[:])
	}
	if matches != 1 {
		return User{}, 0, ErrAuth
	}
	return selected, timestamp, nil
}
