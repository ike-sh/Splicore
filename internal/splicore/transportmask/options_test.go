package transportmask

import (
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	"strings"
	"testing"
)

func TestBoundedMaskParametersAndExactSecret(t *testing.T) {
	valid := Options{FinalMask: &FinalMask{TCP: []TCPMask{{Type: "sudoku", Settings: &Sudoku{ASCII: "prefer_ascii", PaddingMin: 0, PaddingMax: 3}}}}}
	if valid.Validate() != nil {
		t.Fatal("reference profile rejected")
	}
	for _, change := range []func(*Options){
		func(o *Options) { o.FinalMask = nil }, func(o *Options) { o.FinalMask.TCP = nil },
		func(o *Options) { o.FinalMask.TCP[0].Type = "unknown" }, func(o *Options) { o.FinalMask.TCP[0].Settings = nil },
		func(o *Options) { o.FinalMask.TCP[0].Settings.PaddingMin = -1 }, func(o *Options) { o.FinalMask.TCP[0].Settings.PaddingMax = 255 },
		func(o *Options) { o.FinalMask.TCP[0].Settings.ASCII = "custom" },
	} {
		b, _ := json.Marshal(valid)
		var o Options
		_ = json.Unmarshal(b, &o)
		change(&o)
		if o.Validate() == nil {
			t.Fatal("unqualified mask accepted")
		}
	}
	p, err := GeneratePassword()
	if err != nil || ValidatePassword(p) != nil {
		t.Fatal("generated password invalid")
	}
	upper := secret.New(strings.ToUpper(p.Reveal()))
	if ValidatePassword(upper) != nil || upper.Reveal() != strings.ToUpper(p.Reveal()) {
		t.Fatal("exact migrated seed rejected or normalized")
	}
	for _, value := range []string{"", strings.Repeat("z", 32), p.Reveal() + "0", p.Reveal()[:31]} {
		if ValidatePassword(secret.New(value)) == nil {
			t.Fatal("invalid secret accepted")
		}
	}
}

func FuzzMaskOptionParser(f *testing.F) {
	f.Add([]byte(`{"finalmask":{"tcp":[{"type":"sudoku","settings":{"ascii":"prefer_ascii","padding_min":0,"padding_max":3}}]}}`))
	f.Add([]byte(`{"finalmask":{"tcp":[{"type":"sudoku","settings":{"ascii":"prefer_ascii","ascii":"custom","padding_max":3}}]}}`))
	f.Add([]byte(`{"finalmask":{"udp":[]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var o Options
		if jsonstrict.Decode(b, &o) != nil || o.Validate() != nil {
			return
		}
		encoded, err := json.Marshal(o)
		if err != nil {
			t.Fatal("encode accepted options")
		}
		var roundtrip Options
		if jsonstrict.Decode(encoded, &roundtrip) != nil || roundtrip.Validate() != nil {
			t.Fatal("accepted profile failed canonical roundtrip")
		}
		if len(roundtrip.FinalMask.TCP) != 1 || roundtrip.FinalMask.TCP[0].Type != "sudoku" {
			t.Fatal("parser expanded feature surface")
		}
	})
}

func TestMaskParserRequiresExplicitNonNullParameters(t *testing.T) {
	for _, settings := range []string{
		`{"ascii":"prefer_ascii","padding_min":null,"padding_max":3}`,
		`{"ascii":"prefer_ascii","padding_max":3}`,
		`{"ascii":"prefer_ascii","padding_min":0,"padding_max":null}`,
		`{"ascii":null,"padding_min":0,"padding_max":3}`,
		`{"ascii":"prefer_ascii","padding_min":0,"padding_max":3,"extra":0}`,
		`{"ascii":"prefer_ascii","padding_min":0,"padding_min":0,"padding_max":3}`,
	} {
		var options Options
		data := []byte(`{"finalmask":{"tcp":[{"type":"sudoku","settings":` + settings + `}]}}`)
		if jsonstrict.Decode(data, &options) == nil && options.Validate() == nil {
			t.Fatal("ambiguous feature parameters accepted")
		}
	}
}
