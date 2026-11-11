package secretvault

import (
	"bytes"
	"testing"
)

func TestAuthenticatedEncryption(t *testing.T) {
	v, err := New("test-key", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("dummy-password")
	aad := []byte("test-owned-credential")
	a, _ := v.Seal(plain, aad)
	b, _ := v.Seal(plain, aad)
	if bytes.Equal(a, b) || bytes.Contains(a, plain) {
		t.Fatal("nonce reused or plaintext stored")
	}
	got, err := v.Open(a, aad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("decrypt failed")
	}
	if _, err = v.Open(a, []byte("different-owner")); err == nil {
		t.Fatal("owner substitution accepted")
	}
	a[len(a)-1] ^= 1
	if _, err = v.Open(a, aad); err == nil {
		t.Fatal("tampering accepted")
	}
	if _, err = New("test", []byte{1}); err == nil {
		t.Fatal("short key accepted")
	}
}
