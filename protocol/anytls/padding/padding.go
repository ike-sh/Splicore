// Package padding applies immutable, validated AnyTLS plaintext write policies.
package padding

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

const Default = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"

const MaxScheme = 8192
const MaxRules = 64
const MaxSteps = 32

type step struct {
	low, high int
	check     bool
}
type Scheme struct {
	text, hash string
	stop       int
	rules      map[int][]step
}

func integer(s string) (int, error) {
	if s == "" || len(s) > 5 {
		return 0, wire.ErrProtocol
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, wire.ErrProtocol
		}
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, wire.ErrProtocol
	}
	return int(v), nil
}

func Parse(text string) (*Scheme, error) {
	if len(text) == 0 || len(text) > MaxScheme || strings.ContainsAny(text, "\r\x00") {
		return nil, wire.ErrProtocol
	}
	s := &Scheme{text: text, rules: make(map[int][]step)}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) > MaxRules+1 {
		return nil, wire.ErrProtocol
	}
	stopSeen := false
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, wire.ErrProtocol
		}
		if key == "stop" {
			if stopSeen {
				return nil, wire.ErrProtocol
			}
			n, err := integer(value)
			if err != nil || n > MaxRules {
				return nil, wire.ErrProtocol
			}
			s.stop, stopSeen = n, true
			continue
		}
		index, err := integer(key)
		if err != nil || index >= MaxRules {
			return nil, wire.ErrProtocol
		}
		if _, duplicate := s.rules[index]; duplicate {
			return nil, wire.ErrProtocol
		}
		tokens := strings.Split(value, ",")
		if len(tokens) > MaxSteps || index == 0 && len(tokens) != 1 {
			return nil, wire.ErrProtocol
		}
		steps := make([]step, 0, len(tokens))
		budget := 0
		for i, token := range tokens {
			if token == "c" {
				if i == 0 || i == len(tokens)-1 || tokens[i-1] == "c" {
					return nil, wire.ErrProtocol
				}
				steps = append(steps, step{check: true})
				continue
			}
			lowText, highText, ok := strings.Cut(token, "-")
			if !ok {
				return nil, wire.ErrProtocol
			}
			low, e1 := integer(lowText)
			high, e2 := integer(highText)
			if e1 != nil || e2 != nil || low > high || index != 0 && low < 1 {
				return nil, wire.ErrProtocol
			}
			budget += high
			if budget > 1<<20 {
				return nil, wire.ErrProtocol
			}
			steps = append(steps, step{low: low, high: high})
		}
		s.rules[index] = steps
	}
	if !stopSeen {
		return nil, wire.ErrProtocol
	}
	for index := range s.rules {
		if index >= s.stop {
			return nil, wire.ErrProtocol
		}
	}
	h := md5.Sum([]byte(text)) // The public protocol uses MD5 only as a scheme identifier.
	s.hash = hex.EncodeToString(h[:])
	return s, nil
}

func MustDefault() *Scheme     { s, _ := Parse(Default); return s }
func (s *Scheme) Text() string { return s.text }
func (s *Scheme) Hash() string { return s.hash }

// Random is injectable in tests; production uses crypto/rand, never math/rand.
type Random interface{ Between(int, int) (int, error) }
type SecureRandom struct{}

func (SecureRandom) Between(low, high int) (int, error) {
	if low > high || low < 0 {
		return 0, wire.ErrProtocol
	}
	if low == high {
		return low, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(high-low+1)))
	if err != nil {
		return 0, err
	}
	return low + int(n.Int64()), nil
}

func (s *Scheme) AuthLength(r Random) (int, error) {
	if values := s.rules[0]; len(values) != 0 {
		return r.Between(values[0].low, values[0].high)
	}
	return 0, nil
}

// Writer counts one submitted TLS plaintext write, even when its policy splits
// that write. Authentication is packet zero; the first session write is one.
// Only the owning session's serialized writer accesses this object.
type Writer struct {
	conn   io.Writer
	scheme *Scheme
	random Random
	packet int
}

func NewWriter(conn io.Writer, scheme *Scheme, random Random) *Writer {
	if random == nil {
		random = SecureRandom{}
	}
	return &Writer{conn: conn, scheme: scheme, random: random, packet: 1}
}
func (w *Writer) PacketCount() int { return w.packet }
func (w *Writer) Write(data []byte) error {
	index := w.packet
	if w.packet < w.scheme.stop {
		w.packet++
	}
	if index >= w.scheme.stop {
		return wire.WriteAll(w.conn, data)
	}
	for _, value := range w.scheme.rules[index] {
		if value.check {
			if len(data) == 0 {
				return nil
			}
			continue
		}
		target, err := w.random.Between(value.low, value.high)
		if err != nil || target < value.low || target > value.high {
			return wire.ErrProtocol
		}
		if len(data) >= target {
			if err := wire.WriteAll(w.conn, data[:target]); err != nil {
				return err
			}
			data = data[target:]
			continue
		}
		// Padding is a complete Waste frame. A gap shorter than the header
		// cannot be represented and leaves the final data fragment unpadded.
		part := append([]byte(nil), data...)
		if gap := target - len(part); gap >= wire.HeaderSize {
			part, err = wire.AppendFrame(part, wire.Frame{Command: wire.Waste, Payload: make([]byte, gap-wire.HeaderSize)})
			if err != nil {
				return err
			}
		}
		if len(part) != 0 {
			if err = wire.WriteAll(w.conn, part); err != nil {
				return err
			}
		}
		data = nil
	}
	if len(data) != 0 {
		return wire.WriteAll(w.conn, data)
	}
	return nil
}
