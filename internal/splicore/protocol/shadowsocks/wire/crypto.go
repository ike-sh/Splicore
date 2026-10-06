// Package wire implements only canonical Shadowsocks framing. It owns no network
// sockets, routing, domain transactions or crypto primitives.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

var (
	ErrAuth      = errors.New("shadowsocks: authentication failed")
	ErrFrame     = errors.New("shadowsocks: invalid frame")
	ErrReplay    = errors.New("shadowsocks: replay rejected")
	ErrTimestamp = errors.New("shadowsocks: invalid timestamp")
	ErrCapacity  = errors.New("shadowsocks: resource capacity reached")
)

const MaxDatagram = 65507
const MaxPadding = 900

// Key is immutable after construction; all mutable counters/buffers are per flow.
type Key struct {
	Method   module.Method
	Material []byte
	Hash     [16]byte
}

func (*Key) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("ShadowsocksKey{[REDACTED]}")) }
func Keys(method, value string) ([]*Key, error) {
	m, e := module.Lookup(method)
	if e != nil {
		return nil, e
	}
	var raw [][]byte
	if m.Edition == "2022" {
		raw, e = module.DecodeKeys(method, value, true)
	} else {
		if len(value) == 0 || len(value) > 4096 {
			return nil, ErrAuth
		}
		raw = [][]byte{classicPasswordKey([]byte(value), m.KeySize)}
	}
	if e != nil {
		return nil, e
	}
	out := make([]*Key, 0, len(raw))
	for _, b := range raw {
		sum := blake3.Sum256(b)
		k := &Key{Method: m, Material: b}
		copy(k.Hash[:], sum[:16])
		out = append(out, k)
	}
	return out, nil
}

// Classic AEAD retains the specified EVP_BytesToKey password composition.
// MD5 here derives the legacy master key; AEAD authentication uses its cipher.
func classicPasswordKey(password []byte, size int) []byte {
	key := make([]byte, 0, size+md5.Size)
	var previous []byte
	for len(key) < size {
		h := md5.New()
		_, _ = h.Write(previous)
		_, _ = h.Write(password)
		previous = h.Sum(nil)
		key = append(key, previous...)
	}
	clear(previous)
	return key[:size:size]
}
func (k *Key) subkey(salt []byte, context string) ([]byte, error) {
	if k.Method.Edition == "2017" {
		return hkdf.Key(sha1.New, k.Material, salt, "ss-subkey", k.Method.KeySize)
	}
	material := make([]byte, 0, len(k.Material)+len(salt))
	material = append(material, k.Material...)
	material = append(material, salt...)
	b := make([]byte, k.Method.KeySize)
	blake3.DeriveKey(b, context, material)
	clear(material)
	return b, nil
}
func (k *Key) aead(salt []byte) (cipher.AEAD, error) {
	b, e := k.subkey(salt, "shadowsocks 2022 session subkey")
	if e != nil {
		return nil, e
	}
	defer clear(b)
	if k.Method.Name == "chacha20-ietf-poly1305" || k.Method.Name == "2022-blake3-chacha20-poly1305" {
		return chacha20poly1305.New(b)
	}
	c, e := aes.NewCipher(b)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(c)
}
func (k *Key) block() (cipher.Block, error) { return aes.NewCipher(k.Material) }
func (k *Key) identity(salt []byte) (cipher.Block, error) {
	b, e := k.subkey(salt, "shadowsocks 2022 identity subkey")
	if e != nil {
		return nil, e
	}
	defer clear(b)
	return aes.NewCipher(b)
}
func random(n int) ([]byte, error) { b := make([]byte, n); _, e := rand.Read(b); return b, e }
func randomPadding() ([]byte, error) {
	v, e := rand.Int(rand.Reader, bigPaddingBound)
	if e != nil {
		return nil, e
	}
	return random(int(v.Int64()) + 1)
}
func timestampOK(epoch uint64, now time.Time) bool {
	if epoch > math.MaxInt64 {
		return false
	}
	second := now.Unix()
	if second < 0 {
		return false
	}
	stamp := int64(epoch)
	if stamp > second {
		return stamp-second <= 30
	}
	return second-stamp <= 30
}
func increment(nonce []byte) error {
	for n := range nonce {
		nonce[n]++
		if nonce[n] != 0 {
			return nil
		}
	}
	return ErrCapacity
}
func writeAll(w io.Writer, b []byte) error {
	// A single write preserves SIP022's initial header requirement. A short write
	// cannot be repaired without splitting that header and poisons the stream.
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return e
}
func putTime(b []byte, now time.Time) { binary.BigEndian.PutUint64(b, uint64(now.Unix())) }
