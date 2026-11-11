package address

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func TestSOCKSWildcardAndCanonicalVectors(t *testing.T) {
	for _, tc := range []struct {
		e    access.Endpoint
		wire string
	}{
		{access.Endpoint{Host: "0.0.0.0"}, "01000000000000"},
		{access.Endpoint{Host: "::", Port: 53}, "04000000000000000000000000000000000035"},
		{access.Endpoint{Host: "example.com", Port: 443}, "030b6578616d706c652e636f6d01bb"},
	} {
		want, _ := hex.DecodeString(tc.wire)
		got, err := MarshalSOCKS(tc.e)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("wire %x: %v", got, err)
		}
		e, err := ReadSOCKS(bytes.NewReader(want))
		if err != nil || e != tc.e {
			t.Fatalf("address %+v: %v", e, err)
		}
	}
}

func FuzzSOCKSAddress(f *testing.F) {
	for _, s := range []string{"01000000000000", "030b6578616d706c652e636f6d01bb", "0420010db800000000000000000000000101bb", "030001bb", "ff"} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		e, err := ReadSOCKS(r)
		if err != nil {
			return
		}
		encoded, err := MarshalSOCKS(e)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadSOCKS(bytes.NewReader(encoded))
		if err != nil || got != e {
			t.Fatal("semantic address changed", err)
		}
		if len(encoded) > 259 || r.Len() > len(b) {
			t.Fatal("unbounded address")
		}
	})
}
