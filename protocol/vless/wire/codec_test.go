package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"testing"
)

func TestRequestAndCanonicalAddress(t *testing.T) {
	for _, v := range []struct{ host, encoded string }{{"127.0.0.1", "01bb017f000001"}, {"::1", "01bb0300000000000000000000000000000001"}, {"example.invalid", "01bb020f6578616d706c652e696e76616c6964"}} {
		dst := access.Endpoint{Host: v.host, Port: 443}
		a, err := Address(dst)
		if err != nil || hex.EncodeToString(a) != v.encoded {
			t.Fatal("address vector", v.host, err)
		}
		var b bytes.Buffer
		q := Request{UUID: [16]byte{17}, Command: TCP, Destination: dst}
		if err := WriteRequest(&b, q); err != nil {
			t.Fatal(err)
		}
		got, err := ReadRequest(&b)
		if err != nil || got != q || b.Len() != 0 {
			t.Fatal("request boundary", got, err)
		}
	}
	addon := append([]byte{10, byte(len("xtls-rprx-vision"))}, "xtls-rprx-vision"...)
	b := append(make([]byte, 17), byte(len(addon)))
	b = append(b, addon...)
	if _, err := ReadRequest(bytes.NewReader(b)); !errors.Is(err, ErrFlow) {
		t.Fatal("Vision addon accepted", err)
	}
	for _, b := range [][]byte{nil, {1}, make([]byte, 18)} {
		if _, err := ReadRequest(bytes.NewReader(b)); err == nil {
			t.Fatal("truncated request accepted")
		}
	}
}
func TestXUDPFramesAndBounds(t *testing.T) {
	for _, size := range []int{0, 1, 900, 4096, 8192} {
		var b bytes.Buffer
		payload := bytes.Repeat([]byte{42}, size)
		want := Frame{Session: 7, Status: 1, Options: 1, Network: 2, Destination: access.Endpoint{Host: "::1", Port: 53}, Payload: payload}
		if err := WriteFrame(&b, want); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFrame(&b)
		if err != nil || got.Session != want.Session || got.Destination != want.Destination || !bytes.Equal(got.Payload, payload) || b.Len() != 0 {
			t.Fatal("XUDP boundary", err)
		}
		clear(b.Bytes())
		if !bytes.Equal(got.Payload, payload) {
			t.Fatal("frame retained producer storage")
		}
	}
	for _, b := range [][]byte{nil, {0, 3, 0, 0, 2}, {2, 1}, {0, 4, 0, 0, 255, 0}} {
		if _, err := ReadFrame(bytes.NewReader(b)); err == nil {
			t.Fatal("bad frame accepted")
		}
	}
}
func FuzzRequestAndXUDP(f *testing.F) {
	f.Add([]byte{0})
	var b bytes.Buffer
	_ = WriteRequest(&b, Request{UUID: [16]byte{1}, Command: TCP, Destination: access.Endpoint{Host: "127.0.0.1", Port: 80}})
	f.Add(b.Bytes())
	b.Reset()
	_ = WriteFrame(&b, Frame{Status: 1, Network: 2, Destination: access.Endpoint{Host: "localhost", Port: 53}, Payload: []byte("synthetic")})
	f.Add(b.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 70000 {
			return
		}
		_, _ = ReadRequest(bytes.NewReader(b))
		_ = ReadResponse(bytes.NewReader(b))
		if f, err := ReadFrame(bytes.NewReader(b)); err == nil {
			var encoded bytes.Buffer
			if err := WriteFrame(&encoded, f); err != nil {
				t.Fatal(err)
			}
			got, err := ReadFrame(&encoded)
			if err != nil || got.Session != f.Session || got.Destination != f.Destination || !bytes.Equal(got.Payload, f.Payload) {
				t.Fatal("frame semantic roundtrip")
			}
		}
	})
}
