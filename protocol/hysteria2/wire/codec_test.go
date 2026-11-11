package wire

import (
	"bytes"
	"testing"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func TestTCPFramingAndBounds(t *testing.T) {
	for _, address := range []string{"127.0.0.1:80", "[::1]:443", "synthetic.invalid:53"} {
		dst, err := Endpoint(address)
		if err != nil {
			t.Fatal(err)
		}
		var request bytes.Buffer
		if err := WriteRequest(&request, dst); err != nil {
			t.Fatal(err)
		}
		frame, err := quicvarint.Read(&request)
		if err != nil || frame != TCPRequest {
			t.Fatal("frame type")
		}
		got, err := ReadRequest(&request)
		if err != nil || got != dst || request.Len() != 0 {
			t.Fatal("destination boundary", got, err)
		}
		for _, ok := range []bool{true, false} {
			var response bytes.Buffer
			_ = WriteResponse(&response, ok)
			err := ReadResponse(&response)
			if ok && err != nil || !ok && err != ErrRejected {
				t.Fatal("response")
			}
		}
	}
	for _, b := range [][]byte{nil, {0}, quicvarint.Append(nil, 2049), append(quicvarint.Append(nil, 1), 'x')} {
		if _, err := ReadRequest(bytes.NewReader(b)); err == nil {
			t.Fatal("malformed request accepted")
		}
	}
}
func TestFragmentOwnershipReorderAndBounds(t *testing.T) {
	dst := access.Endpoint{Host: "127.0.0.1", Port: 443}
	payload := bytes.Repeat([]byte{17, 42}, 2048)
	frames, err := Fragments(7, 11, dst, payload)
	if err != nil || len(frames) < 2 {
		t.Fatal(err)
	}
	var assembly Assembly
	for i := len(frames) - 1; i >= 0; i-- {
		d, err := DecodeDatagram(frames[i])
		if err != nil {
			t.Fatal(err)
		}
		clear(frames[i])
		got, ok := assembly.Add(d)
		clear(d.Payload)
		if ok {
			if i != 0 || !bytes.Equal(got.Payload, payload) || got.Destination != dst {
				t.Fatal("fragment ownership or ordering")
			}
		}
	}
	if _, err := Fragments(1, 2, dst, make([]byte, 4097)); err == nil {
		t.Fatal("oversize datagram")
	}
	if _, ok := assembly.Add(Datagram{Count: 2, Index: 2, Destination: dst, Payload: []byte{1}}); ok {
		t.Fatal("invalid index")
	}
	for i := range 1000 {
		_, _ = assembly.Add(Datagram{Session: uint32(i), Count: 2, Destination: dst, Payload: []byte{1}})
	}
	if len(assembly.pending) > 128 {
		t.Fatal("unbounded fragment cache")
	}
}
func FuzzTCPAndDatagram(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte("127.0.0.1:443"))
	b, _ := EncodeDatagram(Datagram{Session: 1, Count: 1, Destination: access.Endpoint{Host: "127.0.0.1", Port: 80}, Payload: []byte("synthetic")})
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		_, _ = ReadRequest(bytes.NewReader(b))
		_ = ReadResponse(bytes.NewReader(b))
		if d, err := DecodeDatagram(b); err == nil {
			encoded, err := EncodeDatagram(d)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeDatagram(encoded)
			if err != nil || again.Destination != d.Destination || !bytes.Equal(again.Payload, d.Payload) {
				t.Fatal("datagram semantic roundtrip")
			}
			var a Assembly
			_, _ = a.Add(d)
		}
	})
}
