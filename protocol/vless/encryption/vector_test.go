package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestPinnedReferenceDeterministicVectors(t *testing.T) {
	data, e := os.ReadFile("testdata/reference-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct {
		Context, Key, Derived, Header, Plaintext, Ciphertext, Nonce string
		AES                                                         bool
	}
	if e = json.Unmarshal(data, &rows); e != nil {
		t.Fatal(e)
	}
	decode := func(s string) []byte {
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	for _, v := range rows {
		key, context := decode(v.Key), decode(v.Context)
		if !bytes.Equal(derive(context, key), decode(v.Derived)) {
			t.Fatal("BLAKE3 reference mismatch")
		}
		a := newCryptor(context, key, v.AES)
		got := a.seal(decode(v.Plaintext), decode(v.Header))
		if !bytes.Equal(got, decode(v.Ciphertext)) || !bytes.Equal(a.counter[:], decode(v.Nonce)) {
			t.Fatal("AEAD/nonce reference mismatch")
		}
		if size, e := headerSize(decode(v.Header)); e != nil || size != len(got) {
			t.Fatal("header reference mismatch")
		}
	}
}

func TestPinnedReferenceKeyAndPaddingVectors(t *testing.T) {
	data, e := os.ReadFile("testdata/reference-key-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors struct {
		Hybrid  map[string]string `json:"hybrid"`
		Padding []struct {
			Input      string
			Accepted   bool
			Lens, Gaps [][3]int
		} `json:"padding"`
	}
	if e = json.Unmarshal(data, &vectors); e != nil {
		t.Fatal(e)
	}
	v := vectors.Hybrid
	dec := func(name string) []byte {
		b, e := hex.DecodeString(v[name])
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	kem, e := mlkem.NewDecapsulationKey768(dec("seed"))
	if e != nil {
		t.Fatal(e)
	}
	shared, e := kem.Decapsulate(dec("kem_ciphertext"))
	if e != nil || !bytes.Equal(shared, dec("kem_secret")) || !bytes.Equal(kem.EncapsulationKey().Bytes(), dec("kem_public")) {
		t.Fatal("pinned ML-KEM seed/public/ciphertext vector", e)
	}
	x, e := ecdh.X25519().NewPrivateKey(dec("x_private"))
	if e != nil {
		t.Fatal(e)
	}
	y, e := ecdh.X25519().NewPublicKey(dec("y_public"))
	if e != nil {
		t.Fatal(e)
	}
	xs, e := x.ECDH(y)
	if e != nil || !bytes.Equal(xs, dec("x_secret")) || !bytes.Equal(x.PublicKey().Bytes(), dec("x_public")) {
		t.Fatal("pinned X25519 vector", e)
	}
	pfs := append(shared, xs...)
	united := append(append([]byte(nil), pfs...), dec("nfs")...)
	if !bytes.Equal(pfs, dec("pfs")) || !bytes.Equal(united, dec("united")) {
		t.Fatal("PFS/united ordering")
	}
	a := newCryptor(dec("context"), united, true)
	if !bytes.Equal(a.seal(dec("plaintext"), dec("header")), dec("ciphertext")) {
		t.Fatal("pinned hybrid united KDF/AEAD vector")
	}
	for _, p := range vectors.Padding {
		text := method + ".native.1rtt."
		if p.Input != "" {
			text += p.Input + "."
		}
		text += base64.RawURLEncoding.EncodeToString(dec("x_public"))
		cfg, e := ParseClient(text)
		if p.Input == "100-35-35.101-0-0" {
			if e == nil {
				t.Fatal("out-of-range probability accepted")
			}
			continue
		}
		if (e == nil) != p.Accepted {
			t.Fatal("padding acceptance mismatch", p.Input)
		}
		if e != nil {
			continue
		}
		tuples := cfg.padding

		var lens, gaps [][3]int
		for n, p := range tuples {
			v := [3]int{p.probability, p.low, p.high}
			if n%2 == 0 {
				lens = append(lens, v)
			} else {
				gaps = append(gaps, v)
			}
		}
		if !reflect.DeepEqual(lens, p.Lens) || !reflect.DeepEqual(gaps, p.Gaps) {
			t.Fatal("padding tuple mismatch", p.Input)
		}
	}
}

func TestPinnedReferenceRekeyVectors(t *testing.T) {
	data, e := os.ReadFile("testdata/reference-record-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct {
		AES                                    bool
		Key, Context, Counter, Plaintext, Wire string
		NextNonce                              string `json:"next_nonce"`
	}
	if e = json.Unmarshal(data, &rows); e != nil {
		t.Fatal(e)
	}
	decode := func(s string) []byte {
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	for _, v := range rows {
		transport := &memoryConn{}
		c := &Conn{Conn: transport, tx: newCryptor(decode(v.Context), decode(v.Key), v.AES), united: decode(v.Key), aesMode: v.AES}
		copy(c.tx.counter[:], decode(v.Counter))
		if _, e = c.Write(decode(v.Plaintext)); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(transport.output.Bytes(), decode(v.Wire)) || !bytes.Equal(c.tx.counter[:], decode(v.NextNonce)) {
			t.Fatal("pinned record fragmentation/nonce/rekey mismatch")
		}
	}
}
