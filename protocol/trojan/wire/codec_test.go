package wire

import (
	"bytes"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"io"
	"testing"
)

type fragmented struct{ io.Reader }

func (r fragmented) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.Reader.Read(b)
}
func TestRequestBoundaries(t *testing.T) {
	key := Derive(secret.New("synthetic-Trojan-user-A"))
	for _, dst := range []access.Endpoint{{Host: "127.0.0.1", Port: 53}, {Host: "::1", Port: 443}, {Host: "synthetic.test", Port: 8080}} {
		for _, command := range []byte{Connect, Associate} {
			b, err := EncodeRequest(key, command, dst)
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("first-payload"), 320000)
			r := bytes.NewReader(append(bytes.Clone(b), payload...))
			v, err := ReadRequest(fragmented{r})
			if err != nil || v.Key != key || v.Command != command || v.Destination != dst {
				t.Fatal("fragmented request mismatch")
			}
			tail, _ := io.ReadAll(r)
			if !bytes.Equal(tail, payload) {
				t.Fatal("coalesced payload consumed")
			}
			for n := 0; n < len(b); n++ {
				if _, err := ReadRequest(bytes.NewReader(b[:n])); err == nil {
					t.Fatal("truncated request accepted", n)
				}
			}
		}
	}
	b, _ := EncodeRequest(key, Connect, access.Endpoint{Host: "127.0.0.1", Port: 443})
	for _, mutation := range []func([]byte){func(b []byte) { b[0] = 'z' }, func(b []byte) { b[56] = 'x' }, func(b []byte) { b[57] = 'x' }, func(b []byte) { b[58] = 0x7f }, func(b []byte) { b[59] = 2 }, func(b []byte) { b[len(b)-1] = 'x' }, func(b []byte) { b[len(b)-4] = 0; b[len(b)-3] = 0 }} {
		v := bytes.Clone(b)
		mutation(v)
		if _, err := ReadRequest(bytes.NewReader(v)); err == nil {
			t.Fatal("malformed request accepted")
		}
	}
}
func TestAuthenticationAndRedaction(t *testing.T) {
	a, b := Derive(secret.New("synthetic-Trojan-user-A")), Derive(secret.New("synthetic-Trojan-user-B"))
	users := []User{{"A", a}, {"B", b}}
	for _, c := range []struct {
		k     Key
		id    string
		valid bool
	}{{a, "A", true}, {b, "B", true}, {Derive(secret.New("synthetic-invalid-user")), "", false}} {
		id, ok := Match(c.k, users)
		if id != c.id || ok != c.valid {
			t.Fatal("credential identity mismatch")
		}
	}
	if _, ok := Match(a, nil); ok {
		t.Fatal("empty generation authenticated")
	}
	if fmt.Sprintf("%v/%s/%#v", a, a, a) != "[REDACTED]/[REDACTED]/[REDACTED]" {
		t.Fatal("derived credential disclosed")
	}
}
func TestPacketBoundaries(t *testing.T) {
	for _, dst := range []access.Endpoint{{Host: "127.0.0.1", Port: 53}, {Host: "::1", Port: 53}, {Host: "synthetic.test", Port: 53}} {
		for _, size := range []int{0, 1, 8192, 65507, MaxPayload} {
			payload := bytes.Repeat([]byte{42}, size)
			b, err := EncodePacket(payload, dst)
			if err != nil {
				t.Fatal(err)
			}
			r := bytes.NewReader(append(bytes.Clone(b), b...))
			for i := 0; i < 2; i++ {
				p, d, e := ReadPacket(fragmented{r})
				if e != nil || d != dst || !bytes.Equal(p, payload) {
					t.Fatal("packet boundary lost", size)
				}
			}
			if r.Len() != 0 {
				t.Fatal("unconsumed frame bytes")
			}
			if len(b) > 0 {
				if _, _, e := ReadPacket(bytes.NewReader(b[:len(b)-1])); e == nil {
					t.Fatal("truncation accepted")
				}
			}
		}
	}
	if _, e := EncodePacket(make([]byte, MaxPayload+1), access.Endpoint{Host: "127.0.0.1", Port: 53}); e == nil {
		t.Fatal("oversized payload accepted")
	}
	b, _ := EncodePacket([]byte("packet"), access.Endpoint{Host: "127.0.0.1", Port: 53})
	b[9] = 'x'
	if _, _, e := ReadPacket(bytes.NewReader(b)); e == nil {
		t.Fatal("bad delimiter accepted")
	}
}
func FuzzTrojanRequest(f *testing.F) {
	k := Derive(secret.New("synthetic-fuzz-password"))
	b, _ := EncodeRequest(k, Connect, access.Endpoint{Host: "synthetic.test", Port: 443})
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 70000 {
			return
		}
		v, err := ReadRequest(bytes.NewReader(b))
		if err == nil {
			encoded, e := EncodeRequest(v.Key, v.Command, v.Destination)
			if e != nil {
				t.Fatal(e)
			}
			v2, e := ReadRequest(bytes.NewReader(encoded))
			if e != nil || v != v2 {
				t.Fatal("request round trip")
			}
		}
	})
}
func FuzzTrojanUDPFrame(f *testing.F) {
	b, _ := EncodePacket([]byte("fixture"), access.Endpoint{Host: "::1", Port: 53})
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 70000 {
			return
		}
		p, d, err := ReadPacket(bytes.NewReader(b))
		if err == nil {
			encoded, e := EncodePacket(p, d)
			if e != nil {
				t.Fatal(e)
			}
			p2, d2, e := ReadPacket(bytes.NewReader(encoded))
			if e != nil || d2 != d || !bytes.Equal(p, p2) {
				t.Fatal("UDP round trip")
			}
		}
	})
}
