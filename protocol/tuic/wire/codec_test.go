package wire

import (
	"bytes"
	"encoding/hex"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"testing"
)

func TestCanonicalAddressAndCommands(t *testing.T) {
	for _, v := range []struct{ host, hex string }{{"127.0.0.1", "017f00000101bb"}, {"::1", "020000000000000000000000000000000101bb"}, {"example.invalid", "000f6578616d706c652e696e76616c696401bb"}} {
		dst := access.Endpoint{Host: v.host, Port: 443}
		b, err := Address(dst)
		if err != nil || hex.EncodeToString(b) != v.hex {
			t.Fatalf("address %s: %x %v", v.host, b, err)
		}
		got, err := ReadAddress(bytes.NewReader(b), false)
		if err != nil || got != dst {
			t.Fatal(got, err)
		}
		frame, _ := ConnectFrame(dst)
		r := bytes.NewReader(frame)
		cmd, err := Head(r)
		if err != nil || cmd != Connect {
			t.Fatal("connect command")
		}
		got, err = ReadAddress(r, false)
		if err != nil || got != dst || r.Len() != 0 {
			t.Fatal("connect address")
		}
	}
	for _, b := range [][]byte{nil, {5}, {4, 1}, {5, 5}, {5, 255}} {
		if _, err := Head(bytes.NewReader(b)); err == nil {
			t.Fatal("bad header accepted")
		}
	}
	if _, err := ReadAddress(bytes.NewReader([]byte{255}), false); err == nil {
		t.Fatal("missing connect address accepted")
	}
}
func TestDatagramFragmentOwnership(t *testing.T) {
	dst := access.Endpoint{Host: "::1", Port: 443}
	payload := bytes.Repeat([]byte("owned-tuic-fragments"), 3000)
	frames, err := Fragments(7, 11, dst, payload)
	if err != nil {
		t.Fatal(err)
	}
	var a Assembly
	for i := len(frames) - 1; i >= 0; i-- {
		d, err := Decode(frames[i])
		if err != nil {
			t.Fatal(err)
		}
		clear(frames[i])
		got, ok := a.Add(d)
		clear(d.Payload)
		if ok {
			if i != 0 || got.Destination != dst || !bytes.Equal(got.Payload, payload) {
				t.Fatal("fragment reorder or buffer reuse")
			}
		}
	}
	for i := range 1000 {
		a.Add(Datagram{Association: uint16(i), Count: 2, Index: 1, Payload: []byte{1}})
	}
	if len(a.pending) > 128 {
		t.Fatal("unbounded assembly")
	}
	if _, err := Fragments(1, 2, dst, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("oversize payload")
	}
}
func FuzzCommandsAndPackets(f *testing.F) {
	f.Add([]byte{5, 4})
	b, _ := ConnectFrame(access.Endpoint{Host: "127.0.0.1", Port: 80})
	f.Add(b)
	b, _ = Encode(Datagram{Count: 1, Destination: access.Endpoint{Host: "::1", Port: 53}, Payload: []byte("synthetic")})
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 70000 {
			return
		}
		_, _ = Head(bytes.NewReader(b))
		_, _ = ReadAddress(bytes.NewReader(b), true)
		if d, err := Decode(b); err == nil {
			encoded, err := Encode(d)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(encoded)
			if err != nil || got.Destination != d.Destination || !bytes.Equal(got.Payload, d.Payload) {
				t.Fatal("semantic packet roundtrip")
			}
			var a Assembly
			a.Add(d)
		}
	})
}
