package wire

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha3"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const MaxChunk = 16384

// Chunk owns the state of exactly one direction; its caller serializes access.
type Chunk struct {
	aead    cipher.AEAD
	iv      [16]byte
	counter uint32
	mask    *sha3.SHAKE
	padding bool
	random  io.Reader
}

func NewChunk(r Request, response bool, random io.Reader) (*Chunk, error) {
	if r.Validate() != nil {
		return nil, ErrFrame
	}
	key, iv := r.Material(response)
	c := &Chunk{iv: iv, padding: r.Options&GlobalPadding != 0, random: random}
	switch r.Security {
	case AESGCM:
		c.aead = gcm(key[:])
	case ChaCha:
		first := md5.Sum(key[:])
		second := md5.Sum(first[:])
		expanded := append(append([]byte{}, first[:]...), second[:]...)
		a, err := chacha20poly1305.New(expanded)
		clear(expanded)
		if err != nil {
			return nil, err
		}
		c.aead = a
	}
	if r.Options&LengthMask != 0 {
		c.mask = sha3.NewSHAKE128()
		_, _ = c.mask.Write(iv[:])
	}
	return c, nil
}
func (c *Chunk) next() uint16 {
	var b [2]byte
	_, _ = c.mask.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}
func (c *Chunk) nonce() ([12]byte, error) {
	var n [12]byte
	if c.counter > 65535 {
		return n, ErrCounter
	}
	copy(n[:], c.iv[:12])
	binary.BigEndian.PutUint16(n[:2], uint16(c.counter))
	c.counter++
	return n, nil
}
func (c *Chunk) overhead() int {
	if c.aead != nil {
		return c.aead.Overhead()
	}
	return 0
}
func (c *Chunk) MaxPayload() int {
	n := MaxChunk - c.overhead()
	if c.padding {
		n -= 63
	}
	return n
}
func (c *Chunk) Encode(payload []byte) ([]byte, error) {
	if len(payload) > c.MaxPayload() {
		return nil, ErrFrame
	}
	if c.aead != nil && c.counter > 65535 {
		return nil, ErrCounter
	}
	pad := 0
	if c.padding {
		pad = int(c.next() % 64)
	}
	length := uint16(len(payload) + c.overhead() + pad)
	if c.mask != nil {
		length ^= c.next()
	}
	out := binary.BigEndian.AppendUint16(nil, length)
	if c.aead != nil {
		n, err := c.nonce()
		if err != nil {
			return nil, err
		}
		out = c.aead.Seal(out, n[:], payload, nil)
	} else {
		out = append(out, payload...)
	}
	p := make([]byte, pad)
	if err := randomBytes(c.random, p); err != nil {
		return nil, err
	}
	return append(out, p...), nil
}

// Read authenticates a whole encrypted chunk before exposing any payload.
// Empty data is the standard EOF marker, including on the UDP command.
func (c *Chunk) Read(reader io.Reader) ([]byte, error) {
	if c.aead != nil && c.counter > 65535 {
		return nil, ErrCounter
	}
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	pad := 0
	if c.padding {
		pad = int(c.next() % 64)
	}
	length := binary.BigEndian.Uint16(header[:])
	if c.mask != nil {
		length ^= c.next()
	}
	if int(length) > MaxChunk || int(length) < pad+c.overhead() {
		return nil, ErrFrame
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(reader, data); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	data = data[:len(data)-pad]
	if c.aead != nil {
		n, err := c.nonce()
		if err != nil {
			return nil, err
		}
		data, err = c.aead.Open(data[:0], n[:], data, nil)
		if err != nil {
			return nil, ErrFrame
		}
	}
	if len(data) == 0 {
		return nil, io.EOF
	}
	return data, nil
}
