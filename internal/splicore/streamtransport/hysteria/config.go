package hysteria

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/apernet/quic-go"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

var ErrAuth = errors.New("Hysteria transport admission rejected")
var ErrConfig = errors.New("invalid Hysteria transport configuration or missing TLS/validator")

func carrier(q cfg.QUIC) *quic.Config {
	q = q.Defaults()
	return &quic.Config{EnableDatagrams: true, MaxDatagramFrameSize: 1200, AssumePeerMaxDatagramFrameSize: 1200, DisablePathManager: true, InitialStreamReceiveWindow: q.InitialStreamWindow, MaxStreamReceiveWindow: q.MaxStreamWindow, InitialConnectionReceiveWindow: q.InitialConnectionWindow, MaxConnectionReceiveWindow: q.MaxConnectionWindow, MaxIdleTimeout: time.Duration(q.MaxIdleTimeout) * time.Second, KeepAlivePeriod: time.Duration(q.KeepAlivePeriod) * time.Second, MaxIncomingStreams: q.MaxIncomingStreams, DisablePathMTUDiscovery: q.DisablePathMTUDiscovery}
}
func validTLS(t *tls.Config) bool {
	if t == nil {
		return false
	}
	return len(t.NextProtos) == 0 || len(t.NextProtos) == 1 && t.NextProtos[0] == "h3"
}

func snapshotTLS(t *tls.Config) *tls.Config {
	c := t.Clone()
	if c.RootCAs != nil {
		c.RootCAs = c.RootCAs.Clone()
	}
	if c.ClientCAs != nil {
		c.ClientCAs = c.ClientCAs.Clone()
	}
	c.Certificates = append([]tls.Certificate(nil), c.Certificates...)
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		cert.Certificate = append([][]byte(nil), cert.Certificate...)
		for j := range cert.Certificate {
			cert.Certificate[j] = bytes.Clone(cert.Certificate[j])
		}
		cert.OCSPStaple = bytes.Clone(cert.OCSPStaple)
	}
	// Private keys and TLS callback closures follow crypto/tls's immutable
	// caller contract. Managed profiles supply static owned material.
	return c
}

// CCRX parses the documented bytes/second wire field, never a friendly bps
// string. Numeric zero at the server means unlimited; "auto" selects adaptive
// control. Client zero requests an adaptive server sender.
func CCRX(s string, allowAuto bool) (uint64, bool, error) {
	if allowAuto && s == "auto" {
		return 0, true, nil
	}
	if s == "" || len(s) > 20 {
		return 0, false, ErrAuth
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false, ErrAuth
		}
	}
	v, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		return 0, false, ErrAuth
	}
	return v, false, nil
}

const authPaddingMin = 256
const authPaddingMax = 2048 // exclusive, in ASCII bytes
const authPaddingAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var errPaddingEntropy = errors.New("Hysteria padding entropy rejection limit exceeded")

// Each length has 36 preimages in [0,64512); the remaining 1024 uint16
// values are rejected. No modulo reduction is applied to rejected samples.
func paddingLength(v uint16) (int, bool) {
	const span = authPaddingMax - authPaddingMin
	const limit = (1 << 16) / span * span
	if int(v) >= limit {
		return 0, false
	}
	return authPaddingMin + int(v)%span, true
}

func paddingCharacter(v byte) (byte, bool) {
	const limit = 256 / len(authPaddingAlphabet) * len(authPaddingAlphabet)
	if int(v) >= limit {
		return 0, false
	}
	return authPaddingAlphabet[int(v)%len(authPaddingAlphabet)], true
}

// readPaddingEntropy also terminates for a pathological zero-progress reader.
// crypto/rand.Reader supplies all production entropy; tests inject readers.
func readPaddingEntropy(r io.Reader, b []byte) error {
	for len(b) > 0 {
		n, err := r.Read(b)
		if n < 0 || n > len(b) {
			return io.ErrUnexpectedEOF
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return nil
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func padding() (string, error) { return paddingFrom(rand.Reader) }

func paddingFrom(random io.Reader) (string, error) {
	var seed [2]byte
	length := 0
	for range 128 {
		if err := readPaddingEntropy(random, seed[:]); err != nil {
			return "", err
		}
		if n, ok := paddingLength(binary.BigEndian.Uint16(seed[:])); ok {
			length = n
			break
		}
	}
	if length == 0 {
		return "", errPaddingEntropy
	}
	b := make([]byte, length)
	var sample [256]byte
	used := 0
	// A fixed entropy budget bounds even an all-rejected injected source.
	// Failing the budget returns no padding and never substitutes weak entropy.
	for remaining := 32 * length; used < length && remaining > 0; {
		count := min(len(sample), length-used, remaining)
		if err := readPaddingEntropy(random, sample[:count]); err != nil {
			return "", err
		}
		remaining -= count
		for _, v := range sample[:count] {
			if c, ok := paddingCharacter(v); ok {
				b[used] = c
				used++
			}
		}
	}
	if used != length {
		return "", errPaddingEntropy
	}
	return string(b), nil
}
