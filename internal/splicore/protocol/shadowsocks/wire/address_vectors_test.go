package wire

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func TestCanonicalAddressVectors(t *testing.T) {
	for _, tc := range []struct{ host, encoded, canonical string }{
		{"192.0.2.1", "01c000020101bb", "192.0.2.1"},
		{"2001:db8::1", "0420010db800000000000000000000000101bb", "2001:db8::1"},
		{"example.com", "030b6578616d706c652e636f6d01bb", "example.com"},
		{"::ffff:192.0.2.1", "01c000020101bb", "192.0.2.1"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			want, err := hex.DecodeString(tc.encoded)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Address(access.Endpoint{Host: tc.host, Port: 443})
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("encode: %x %v", got, err)
			}
			got = append(got, 42)
			r := bytes.NewReader(got)
			dst, err := ReadAddress(r)
			if err != nil || dst.Host != tc.canonical || dst.Port != 443 || r.Len() != 1 {
				t.Fatalf("decode: %#v %v", dst, err)
			}
			for n := 0; n < len(want); n++ {
				if _, err := ReadAddress(bytes.NewReader(want[:n])); err == nil {
					t.Fatalf("accepted truncated length %d", n)
				}
			}
		})
	}
	for _, bad := range [][]byte{{0}, {3, 0, 1, 1}, {1, 127, 0, 0, 1, 0, 0}, {3, 1, '/', 1, 1}} {
		if _, err := ReadAddress(bytes.NewReader(bad)); err == nil {
			t.Fatalf("accepted invalid address %x", bad)
		}
	}
}

func TestClassicPasswordKeyVectors(t *testing.T) {
	// OpenSSL EVP_BytesToKey, password "password", no salt, one iteration.
	for _, tc := range []struct {
		size    int
		encoded string
	}{
		{16, "5f4dcc3b5aa765d61d8327deb882cf99"},
		{32, "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08"},
	} {
		if got := hex.EncodeToString(classicPasswordKey([]byte("password"), tc.size)); got != tc.encoded {
			t.Fatalf("key vector %d: %s", tc.size, got)
		}
	}
}
