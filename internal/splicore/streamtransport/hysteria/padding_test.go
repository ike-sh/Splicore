package hysteria

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestAuthPaddingEveryLengthSourceClass(t *testing.T) {
	counts := make([]int, authPaddingMax-authPaddingMin)
	rejected := 0
	for v := 0; v < 1<<16; v++ {
		n, ok := paddingLength(uint16(v))
		if !ok {
			rejected++
			if v < 64512 {
				t.Fatalf("valid source rejected: %d", v)
			}
			continue
		}
		if n < 256 || n >= 2048 {
			t.Fatalf("out of contract: source=%d length=%d", v, n)
		}
		counts[n-256]++
	}
	for i, count := range counts {
		if count != 36 {
			t.Fatalf("length %d has %d accepted preimages, want36", i+256, count)
		}
	}
	if rejected != 1024 {
		t.Fatal("wrong rejected domain", rejected)
	}
	for _, n := range []int{256, 384, 1024, 2047} {
		var seed [2]byte
		binary.BigEndian.PutUint16(seed[:], uint16(n-256))
		p, err := paddingFrom(bytes.NewReader(append(seed[:], make([]byte, n)...)))
		if err != nil || p != strings.Repeat("a", n) {
			t.Fatalf("actual helper boundary%d: length%d err%v", n, len(p), err)
		}
	}
	t.Log("all65536 source values:1792 reachable lengths256..2047,36preimages each,1024rejected;2048excluded")
}

func TestAuthPaddingEveryCharacterSourceClass(t *testing.T) {
	if len(authPaddingAlphabet) != 62 {
		t.Fatal("invalid fixed alphabet")
	}
	counts := map[byte]int{}
	for _, c := range []byte(authPaddingAlphabet) {
		if c >= 128 || counts[c] != 0 {
			t.Fatal("alphabet must be unique ASCII")
		}
		counts[c] = -1
	}
	for c := range counts {
		counts[c] = 0
	}
	for v := 0; v < 256; v++ {
		c, ok := paddingCharacter(byte(v))
		if !ok {
			if v < 248 {
				t.Fatal("accepted class rejected", v)
			}
			continue
		}
		if _, exists := counts[c]; !exists || v >= 248 {
			t.Fatal("invalid accepted mapping", v, c)
		}
		counts[c]++
	}
	for c, count := range counts {
		if count != 4 {
			t.Fatalf("character%c has%d preimages, want4", c, count)
		}
	}
	// Reject both a length sample and every excess byte class, then recover.
	raw := []byte{255, 255, 0, 0, 248, 249, 250, 251, 252, 253, 254, 255}
	raw = append(raw, bytes.Repeat([]byte{61}, 256)...)
	p, err := paddingFrom(bytes.NewReader(raw))
	if err != nil || p != strings.Repeat("9", 256) {
		t.Fatalf("rejection path: length%d err%v", len(p), err)
	}
	t.Log("all256 byte values:248accepted,8rejected;62ASCII symbols have4preimages each;byte length=character length")
}

type paddingRandomError struct{ err error }

func (r paddingRandomError) Read([]byte) (int, error) { return 0, r.err }

type paddingRepeatedByte byte

func (r paddingRepeatedByte) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(r)
	}
	return len(b), nil
}

type paddingDataError struct{ err error }

func (r paddingDataError) Read(b []byte) (int, error) {
	clear(b)
	return len(b), r.err
}

func TestAuthPaddingBoundedRandomFailure(t *testing.T) {
	broken := errors.New("synthetic entropy error")
	for name, r := range map[string]io.Reader{
		"length-error":             paddingRandomError{broken},
		"data-with-error":          paddingDataError{broken},
		"content-error":            io.MultiReader(bytes.NewReader([]byte{0, 0}), paddingRandomError{broken}),
		"length-rejection-budget":  paddingRepeatedByte(255),
		"content-rejection-budget": io.MultiReader(bytes.NewReader([]byte{0, 0}), paddingRepeatedByte(255)),
		"no-progress":              paddingRandomError{},
		"truncated-length":         bytes.NewReader([]byte{0}),
		"truncated-content":        bytes.NewReader([]byte{0, 0, 7}),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := paddingFrom(r)
			if p != "" || err == nil {
				t.Fatalf("partial padding or missing error: %q %v", p, err)
			}
			switch name {
			case "length-error", "content-error", "data-with-error":
				if !errors.Is(err, broken) {
					t.Fatal(err)
				}
			case "length-rejection-budget", "content-rejection-budget":
				if !errors.Is(err, errPaddingEntropy) {
					t.Fatal(err)
				}
			case "no-progress":
				if !errors.Is(err, io.ErrNoProgress) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestAuthPaddingSecureSourceSmoke(t *testing.T) {
	// Supplemental smoke only; exhaustive source-class tests prove the bounds
	// and equal accepted mapping without relying on randomly observed endpoints.
	for range 32 {
		p, err := padding()
		if err != nil || len(p) < 256 || len(p) >= 2048 || strings.Trim(p, authPaddingAlphabet) != "" {
			t.Fatalf("production padding length%d err%v", len(p), err)
		}
	}
}
