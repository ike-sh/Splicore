package wire

import (
	"bytes"
	"github.com/apernet/quic-go/quicvarint"
	"testing"
)

func TestTCPRequestBoundaryMatrix(t *testing.T) {
	field := func(address string, padding uint64, body []byte) []byte {
		b := quicvarint.Append(nil, uint64(len(address)))
		b = append(b, address...)
		b = quicvarint.Append(b, padding)
		return append(b, body...)
	}
	valid := []struct {
		name, address string
		padding       int
	}{
		{"ipv4-no-padding", "127.0.0.1:80", 0},
		{"ipv6-max-padding", "[::1]:443", 4096},
		{"domain-with-padding", "localhost:53", 64},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewReader(field(tc.address, uint64(tc.padding), bytes.Repeat([]byte{7}, tc.padding)))
			got, err := ReadRequest(r)
			if err != nil || Address(got) != tc.address || r.Len() != 0 {
				t.Fatalf("valid boundary: %v %v remaining=%d", got, err, r.Len())
			}
		})
	}
	invalid := []struct {
		name  string
		frame []byte
	}{
		{"missing-address-varint", nil},
		{"truncated-address-varint", []byte{0x40}},
		{"empty-address", []byte{0}},
		{"address-over-limit", quicvarint.Append(nil, 2049)},
		{"truncated-address", append(quicvarint.Append(nil, 12), 'x')},
		{"missing-padding-varint", append(quicvarint.Append(nil, 12), []byte("127.0.0.1:80")...)},
		{"truncated-padding-varint", append(append(quicvarint.Append(nil, 12), []byte("127.0.0.1:80")...), 0x40)},
		{"padding-over-limit", field("127.0.0.1:80", 4097, nil)},
		{"truncated-padding", field("localhost:53", 64, []byte{1, 2})},
		{"target-missing-port", field("localhost", 0, nil)},
		{"target-zero-port", field("localhost:0", 0, nil)},
		{"target-invalid-port", field("localhost:-1", 0, nil)},
		{"target-missing-host", field(":53", 0, nil)},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadRequest(bytes.NewReader(tc.frame))
			if err == nil {
				t.Fatalf("malformed request accepted: %+v", got)
			}
		})
	}
}
