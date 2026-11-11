package vless

import (
	"errors"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func TestEncryptionIntentRejectsWithoutCredentialDisclosure(t *testing.T) {
	for _, field := range []string{"encryption", "decryption"} {
		for _, value := range []string{`""`, `null`, `"mlkem768x25519plus.native.0rtt.synthetic-private-material"`} {
			b := []byte(`{"security":"none","flow":"none","packet_encoding":"xudp","transport":"tcp","` + field + `":` + value + `}`)
			for _, decode := range []func([]byte) error{
				func(b []byte) error { _, err := Decode(b); return err },
				func(b []byte) error {
					b = []byte(strings.Replace(string(b), `"transport":"tcp",`, "", 1))
					_, err := DecodeClientOptions(b)
					return err
				},
			} {
				err := decode(b)
				var typed *identity.Error
				if !errors.As(err, &typed) || typed.Code != identity.Invalid {
					t.Fatalf("encryption intent did not fail explicitly: %v", err)
				}
				if strings.Contains(err.Error(), "synthetic-private-material") {
					t.Fatal("credential in diagnostic")
				}
			}
		}
	}
}

func TestEncryptionOmittedAndNoneRetainPlainSemantics(t *testing.T) {
	for _, member := range []string{"", `,"encryption":"none"`} {
		settings := `{"security":"none","flow":"none","transport":"tcp","packet_encoding":"xudp"` + member + `}`
		if _, err := Decode([]byte(settings)); err != nil {
			t.Fatal("historical plain settings:", err)
		}
		options := strings.Replace(settings, `"transport":"tcp",`, "", 1)
		if _, err := DecodeClientOptions([]byte(options)); err != nil {
			t.Fatal("historical plain options:", err)
		}
	}
}

func TestPlainSudokuRemainsIndependentOfEncryption(t *testing.T) {
	b := []byte(`{"security":"none","flow":"none","transport":"tcp","packet_encoding":"xudp","stream_transport":{"kind":"tcp","final_mask":{"tcp":[{"type":"sudoku","settings":{"password":"synthetic-table","ascii":"prefer_entropy","paddingMin":10,"paddingMax":40}}]}}}`)
	s, err := Decode(b)
	if err != nil || s.Stream == nil || s.Stream.FinalMask == nil {
		t.Fatalf("native plain Sudoku rejected: %v", err)
	}
}
