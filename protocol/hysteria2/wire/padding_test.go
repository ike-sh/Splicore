package wire

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type failedRandom struct{ err error }

func (r failedRandom) Read([]byte) (int, error) { return 0, r.err }

func TestSecurePaddingBoundsAndErrors(t *testing.T) {
	for _, bounds := range [][2]int{{0, 1}, {1, 2}, {64, 512}, {128, 1024}, {256, 2048}} {
		for range 100 {
			p, err := Padding(bounds[0], bounds[1])
			if err != nil || len(p) < bounds[0] || len(p) >= bounds[1] {
				t.Fatalf("%v: length=%d err=%v", bounds, len(p), err)
			}
			if strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" {
				t.Fatal("invalid padding alphabet")
			}
		}
	}
	for _, bounds := range [][2]int{{-1, 1}, {0, 0}, {2, 1}} {
		if _, err := padding(bytes.NewReader(nil), bounds[0], bounds[1]); !errors.Is(err, ErrFrame) {
			t.Fatal(err)
		}
	}
	broken := errors.New("synthetic random source failure")
	if _, err := padding(failedRandom{broken}, 1, 3); !errors.Is(err, broken) {
		t.Fatal(err)
	}
	// A one-value range requires no length entropy; content EOF still propagates.
	if _, err := padding(bytes.NewReader(nil), 1, 2); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if p, err := padding(bytes.NewReader(nil), 0, 1); err != nil || p != "" {
		t.Fatalf("zero: %q %v", p, err)
	}
}

func TestSecurePaddingRejectionSampling(t *testing.T) {
	// Length: range 3 rejects 3, then accepts 2 (maximum exclusive length).
	// Content rejects 248..255, then maps the four equally sized alphabet blocks.
	random := bytes.NewReader([]byte{3, 2, 248, 255, 0, 61, 62})
	p, err := padding(random, 1, 4)
	if err != nil || p != "a9a" {
		t.Fatalf("%q %v", p, err)
	}
	// Every accepted byte maps to each character exactly four times.
	all := make([]byte, 248)
	for i := range all {
		all[i] = byte(i)
	}
	p, err = padding(bytes.NewReader(all), 248, 249)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" {
		if strings.Count(p, string(c)) != 4 {
			t.Fatal("biased alphabet reduction")
		}
	}
}
