package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestCMD4PayloadBoundsAndTruncation(t *testing.T) {
	for _, size := range []int{0, 1, MaxPayload} {
		payload := bytes.Repeat([]byte{37}, size)
		frame := binary.BigEndian.AppendUint16(nil, uint16(size))
		frame = append(frame, payload...)
		got, err := readStreamPayload(bytes.NewReader(frame))
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatal(size, err)
		}
		for n := range len(frame) {
			if _, err := readStreamPayload(bytes.NewReader(frame[:n])); err == nil {
				t.Fatal("truncated", size, n)
			}
		}
	}
	if _, err := readStreamPayload(bytes.NewReader([]byte{255, 255})); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
}

func FuzzCMD4Payload(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 42})
	f.Add([]byte{4, 176})
	f.Add([]byte{255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		r := bytes.NewReader(b)
		for r.Len() > 0 {
			payload, err := readStreamPayload(r)
			if err != nil {
				return
			}
			if len(payload) > MaxPayload {
				t.Fatal("unbounded payload")
			}
		}
		if _, err := readStreamPayload(r); !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	})
}
