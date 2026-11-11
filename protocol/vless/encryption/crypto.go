package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
	"lukechampine.com/blake3"
)

type cryptor struct {
	aead    cipher.AEAD
	counter [12]byte
}

func derive(context, key []byte) []byte {
	out := make([]byte, 32)
	blake3.DeriveKey(out, string(context), key)
	return out
}

func newCryptor(context, key []byte, aesMode bool) *cryptor {
	k := derive(context, key)
	defer clear(k)
	var a cipher.AEAD
	if aesMode {
		block, _ := aes.NewCipher(k)
		a, _ = cipher.NewGCM(block)
	} else {
		a, _ = chacha20poly1305.New(k)
	}
	return &cryptor{aead: a}
}

func (c *cryptor) next() []byte {
	for i := len(c.counter) - 1; i >= 0; i-- {
		c.counter[i]++
		if c.counter[i] != 0 {
			break
		}
	}
	return c.counter[:]
}
func (c *cryptor) seal(p, aad []byte) []byte          { return c.aead.Seal(nil, c.next(), p, aad) }
func (c *cryptor) open(p, aad []byte) ([]byte, error) { return c.aead.Open(nil, c.next(), p, aad) }
func (c *cryptor) terminal() bool {
	for _, b := range c.counter {
		if b != 255 {
			return false
		}
	}
	return true
}

func stream(key, iv []byte) cipher.Stream {
	k := derive([]byte("VLESS"), key)
	defer clear(k)
	block, _ := aes.NewCipher(k)
	return cipher.NewCTR(block, iv)
}

func preferAES() bool {
	return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3 || cpu.ARM64.HasAES && cpu.ARM64.HasPMULL || runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" || cpu.S390X.HasAES && cpu.S390X.HasAESCTR && cpu.S390X.HasGHASH || runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le"
}

func number(n int) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(n)); return b }

func randomBetween(low, high int) (int, error) {
	if high <= low+1 {
		return low, nil
	}
	n, e := rand.Int(rand.Reader, big.NewInt(int64(high-low)))
	if e != nil {
		return 0, e
	}
	return low + int(n.Int64()), nil
}
