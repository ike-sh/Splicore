package sniff

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func record(body []byte) []byte {
	b := []byte{22, 3, 1, byte(len(body) >> 8), byte(len(body))}
	return append(b, body...)
}
func vector(b []byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }
func helloWithExtensions(ext []byte) []byte {
	b := append([]byte{3, 3}, make([]byte, 32)...)
	b = append(b, 0, 0, 2, 0x13, 1, 1, 0)
	b = append(b, vector(ext)...)
	return record(append([]byte{1, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...))
}

func sniExtension(name string) []byte {
	entry := append([]byte{0}, vector([]byte(name))...)
	return append([]byte{0, 0}, vector(vector(entry))...)
}

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(1, len(p))]) }

func TestTLSClientHelloAndRecordFragmentation(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		hello := testkit.ClientHello(t, "www.3verge.com", version)
		for _, split := range []int{0, 1, 2, 3, 4, 7, 37, len(hello) / 2} {
			b := hello
			if split > 0 {
				b = append(record(hello[5:5+split]), record(hello[5+split:])...)
			}
			m, prefix, e := TLS(oneByteReader{bytes.NewReader(b)})
			if e != nil || m.Protocol != "tls" || m.Domain != "www.3verge.com" || !bytes.Equal(prefix, b) {
				t.Fatalf("version %x split %d: %+v %v", version, split, m, e)
			}
		}
	}
}

func TestTLSDNSNameSemantics(t *testing.T) {
	for _, name := range []string{"www.3verge.com", "WWW.3VERGE.COM", "www.3verge.com."} {
		m, _, e := TLS(bytes.NewReader(helloWithExtensions(sniExtension(name))))
		if e != nil || m.Domain != "www.3verge.com" {
			t.Fatal(name, m, e)
		}
	}
	for _, name := range []string{"", "127.0.0.1", "::1", "a..test", "-a.test", "a_.test", "a.test..", "a\x00.test", "a/b.test", "é.test", strings.Repeat("a", 64) + ".test"} {
		if m, _, e := TLS(bytes.NewReader(helloWithExtensions(sniExtension(name)))); e == nil || m != (Metadata{}) {
			t.Fatalf("accepted invalid SNI %q", name)
		}
	}
}

func TestTLSMalformedAndBounded(t *testing.T) {
	ext := sniExtension("www.3verge.com")
	good := helloWithExtensions(ext)
	badExt := append(append([]byte(nil), ext...), 0, 1, 0, 10, 1)
	// Duplicate entries of host_name in the same list are ambiguous.
	entry := append([]byte{0}, vector([]byte("www.3verge.com"))...)
	duplicateName := append([]byte{0, 0}, vector(vector(append(entry, entry...)))...)
	inputs := [][]byte{
		[]byte("GET / HTTP/1.1\r\n"),
		{1, 2, 3, 4, 5},
		{22, 3, 1, 255, 255},
		record([]byte{1, 255, 255, 255}), record(nil), record([]byte{2, 0, 0, 0}),
		helloWithExtensions(nil), helloWithExtensions(sniExtension("")),
		helloWithExtensions(append(append([]byte(nil), ext...), ext...)),
		helloWithExtensions(badExt), helloWithExtensions(duplicateName),
	}
	for n, b := range inputs {
		if m, prefix, e := TLS(bytes.NewReader(b)); e == nil || m != (Metadata{}) || len(prefix) > MaxBytes {
			t.Fatalf("invalid input %d: %+v %v", n, m, e)
		}
	}
	for n := range good {
		if _, _, e := TLS(bytes.NewReader(good[:n])); e == nil {
			t.Fatal("accepted truncation", n)
		}
	}
	// One-byte TLS records cannot force unbounded framing or accumulation.
	var fragments []byte
	for _, b := range append([]byte{1, 0, 0x7f, 0}, make([]byte, 200)...) {
		fragments = append(fragments, record([]byte{b})...)
	}
	if _, _, e := TLS(bytes.NewReader(fragments)); !errors.Is(e, ErrLimit) {
		t.Fatal("record limit", e)
	}
	oversized := record([]byte{1, 0, 0x80, 0})
	if _, _, e := TLS(bytes.NewReader(oversized)); !errors.Is(e, ErrLimit) {
		t.Fatal("hello limit", e)
	}
	// An extra payload suffix inside the last record and subsequent stream bytes
	// are neither inspected again nor lost from the replayed stream.
	withTail := record(append(append([]byte(nil), good[5:]...), []byte("record-tail")...))
	wire := append(append([]byte(nil), withTail...), []byte("stream-tail")...)
	r := bytes.NewReader(wire)
	_, prefix, e := TLS(r)
	if e != nil {
		t.Fatal(e)
	}
	replayed, _ := io.ReadAll(io.MultiReader(bytes.NewReader(prefix), r))
	if !bytes.Equal(replayed, wire) {
		t.Fatal("prefix replay changed bytes")
	}
}

func FuzzTLSClientHello(f *testing.F) {
	good := helloWithExtensions(sniExtension("www.3verge.com"))
	f.Add(good)
	f.Add(append(record(good[5:7]), record(good[7:])...))
	f.Add([]byte{22, 3, 1, 255, 255})
	f.Add(record([]byte{1, 255, 255, 255}))
	f.Add(helloWithExtensions(append(sniExtension("a.test"), sniExtension("b.test")...)))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, prefix, e := TLS(bytes.NewReader(b))
		if len(prefix) > MaxBytes || !bytes.HasPrefix(b, prefix) {
			t.Fatal("unbounded or altered prefix")
		}
		if e != nil && m != (Metadata{}) {
			t.Fatal("metadata published on failure")
		}
		if e == nil && (m.Protocol != "tls" || m.Domain == "") {
			t.Fatal("incomplete metadata")
		}
	})
}

func TestTLSExtensionLengthAfterSNI(t *testing.T) {
	b := helloWithExtensions(append(sniExtension("www.3verge.com"), 0, 13, 0, 2, 0, 0))
	// The complete extension list must be validated, even after an allowed name.
	b[len(b)-4] = 255
	if _, _, e := TLS(bytes.NewReader(b)); e == nil {
		t.Fatal("ignored malformed suffix")
	}
	// The record length is also checked before allocation.
	b = append([]byte(nil), b...)
	binary.BigEndian.PutUint16(b[3:5], MaxRecord+1)
	if _, _, e := TLS(bytes.NewReader(b)); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
}
