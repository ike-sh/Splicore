package snell

import (
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"strings"
	"testing"
)

func TestSettingsAndPSK(t *testing.T) {
	for _, v := range []string{`{"version":5}`, `{"version":6}`} {
		if _, e := Decode([]byte(v)); e != nil {
			t.Fatal(e)
		}
	}
	for _, v := range []string{`{}`, `null`, `{"version":4}`, `{"version":5,"version":6}`, `{"version":6,"psk":"secret"}`, `{"version":6} {}`, `{"version":"6"}`, `{"version":6,"mode":"unsafe-raw"}`} {
		if _, e := Decode([]byte(v)); e == nil {
			t.Fatal("invalid settings accepted")
		}
	}
	a, e := GeneratePSK()
	if e != nil {
		t.Fatal(e)
	}
	b, e := GeneratePSK()
	if e != nil || a.Reveal() == b.Reveal() || len(a.Reveal()) != 43 || ValidatePSK(a) != nil {
		t.Fatal("generation failed")
	}
	for _, s := range []string{"short", strings.Repeat("a", 256), "synthetic,inject", "synthetic\nsecret"} {
		e := ValidatePSK(secret.New(s))
		if e == nil || strings.Contains(e.Error(), s) {
			t.Fatal("invalid credential handling")
		}
	}
	data, _ := json.Marshal(a)
	if strings.Contains(string(data), a.Reveal()) || strings.Contains(fmt.Sprintf("%#v", a), a.Reveal()) {
		t.Fatal("secret leaked")
	}
}
func FuzzSettings(f *testing.F) {
	for _, s := range []string{`{"version":5}`, `{"version":6}`, `null`, `{"version":5,"version":6}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b string) {
		s, e := Decode([]byte(b))
		if e == nil && s.Version != 5 && s.Version != 6 {
			t.Fatal("unsupported parsed")
		}
	})
}
