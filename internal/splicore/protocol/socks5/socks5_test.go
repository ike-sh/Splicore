package socks5

import (
	"bytes"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"io"
	"testing"
)

type shortWriter struct {
	bytes.Buffer
	limit    int
	terminal bool
}

func (w *shortWriter) Write(b []byte) (int, error) {
	n := min(w.limit, len(b))
	w.Buffer.Write(b[:n])
	if w.terminal {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func TestPhase20NegotiationAndPartialFrames(t *testing.T) {
	for _, tc := range []struct {
		b      []byte
		verify bool
		ok     bool
		reply  []byte
	}{
		{[]byte{5, 1, 0}, false, true, []byte{5, 0}}, {[]byte{5, 1, 2, 1, 1, 'u', 1, 'p'}, true, true, []byte{5, 2, 1, 0}},
		{[]byte{5, 1, 0}, true, false, []byte{5, 255}}, {[]byte{5, 1, 2, 1, 1, 'u', 1, 'x'}, true, false, []byte{5, 2, 1, 1}},
		{[]byte{4, 1, 0}, false, false, nil}, {[]byte{5, 0}, false, false, nil}, {[]byte{5, 1, 2, 1, 255, 'u'}, true, false, []byte{5, 2}},
	} {
		w := &shortWriter{limit: 1}
		var verify func(string, string) bool
		if tc.verify {
			verify = func(u, p string) bool { return u == "u" && p == "p" }
		}
		err := AcceptAuthWithVerifier(bytes.NewReader(tc.b), w, verify)
		if (err == nil) != tc.ok || !bytes.Equal(w.Bytes(), tc.reply) {
			t.Fatal("negotiation result", err)
		}
	}
	w := &shortWriter{limit: 1, terminal: true}
	if !errors.Is(WriteFull(w, []byte{5, 0}), io.ErrUnexpectedEOF) || w.Len() != 1 {
		t.Fatal("terminal frame ownership")
	}
	for _, h := range []string{"127.0.0.1", "::1", "synthetic.example"} {
		dst := access.Endpoint{Host: h, Port: 53}
		frame, e := EncodePacket(dst, []byte("packet"))
		if e != nil {
			t.Fatal(e)
		}
		got, p, e := ParsePacket(frame)
		if e != nil || got != dst || string(p) != "packet" {
			t.Fatal("packet roundtrip")
		}
		frame[2] = 1
		if _, _, e = ParsePacket(frame); e == nil {
			t.Fatal("FRAG accepted")
		}
	}
	for _, b := range [][]byte{{5, 1, 0, 9}, {5, 1, 0, 1, 127}, {5, 1, 0, 4, 0}, {5, 1, 0, 3, 0}, {5, 1, 0, 3, 1, 'a', 0}} {
		if _, _, e := ReadCommand(bytes.NewReader(b)); e == nil {
			t.Fatal("truncated request")
		}
	}
}
func FuzzNegotiation(f *testing.F) {
	f.Add([]byte{5, 1, 0})
	f.Add([]byte{5, 1, 2, 1, 1, 'u', 1, 'p'})
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = AcceptAuthWithVerifier(bytes.NewReader(b), io.Discard, func(u, p string) bool { return u == "u" && p == "p" })
	})
}
func FuzzRequest(f *testing.F) {
	f.Add([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = ReadCommand(bytes.NewReader(b)) })
}
func FuzzPacket(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 42})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, p, err := ParsePacket(b)
		if err == nil {
			frame, err := EncodePacket(e, p)
			if err != nil {
				t.Fatal("accepted packet cannot be encoded")
			}
			dst, payload, err := ParsePacket(frame)
			if err != nil || dst != e || !bytes.Equal(payload, p) {
				t.Fatal("semantic packet roundtrip")
			}
		}
	})
}
