package finalmask

import (
	"encoding/json"
	"testing"
)

func TestInvalidConfig(t *testing.T) {
	for _, s := range []string{
		`{"TCP":[{"type":"fragment","settings":{"length":1}}]}`,
		`{"tcp":null}`, `{"tcp":[{"type":"fragment","settings":null}]}`,
		`{"tcp":[{"type":"fragment","settings":{"length":1,"delay":null}}]}`,
		`{"tcp":[{"type":"sudoku","settings":{"Password":"synthetic"}}]}`,
		`{"tcp":[{"type":"header-custom","settings":{"clients":[[{"type":"str","packet":"a","delay":null}]]}}]}`,
		`{"tcp":[]}`, `{"tcp":[{"type":"unknown","settings":{}}]}`,
		`{"tcp":[{"type":"sudoku","settings":{"paddingMin":90,"paddingMax":10}}]}`,
		`{"tcp":[{"type":"sudoku","settings":{"paddingMax":101}}]}`,
		`{"tcp":[{"type":"sudoku","settings":{"customTable":"xxppvvvvv"}}]}`,
		`{"tcp":[{"type":"sudoku","settings":{"ascii":"ascii","customTable":"xxppvvvv"}}]}`,
		`{"tcp":[{"type":"fragment","settings":{"length":"0","delay":0}}]}`,
		`{"tcp":[{"type":"fragment","settings":{"length":"3-1"}}]}`,
		`{"tcp":[{"type":"fragment","settings":{"length":1,"delay":30001}}]}`,
		`{"tcp":[{"type":"fragment","settings":{"length":1,"maxSplit":4097}}]}`,
		`{"tcp":[{"type":"header-custom","settings":{"clients":[[{"rand":1,"type":"str","packet":"x"}]]}}]}`,
		`{"tcp":[{"type":"header-custom","settings":{"clients":[[{"packet":"abc","type":"hex"}]]}}]}`,
		`{"tcp":[{"type":"header-custom","settings":{"clients":[[{"capture":"x"}]]}}]}`,
	} {
		var c Config
		if json.Unmarshal([]byte(s), &c) == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
func TestPacketEncodings(t *testing.T) {
	for _, s := range []string{`{"packet":[65,66,67]}`, `{"type":"str","packet":"ABC"}`, `{"type":"hex","packet":"414243"}`, `{"type":"base64","packet":"QUJD"}`} {
		var v Item
		if json.Unmarshal([]byte(s), &v) != nil {
			t.Fatal(s)
		}
		b, e := v.Bytes()
		if e != nil || string(b) != "ABC" {
			t.Fatal(e)
		}
	}
}
func TestCustomTablesNormalize(t *testing.T) {
	v, e := Decode(Mask{"sudoku", json.RawMessage(`{"password":"synthetic","customTable":"ignored","customTables":["xxppvvvv"," XX PP VVVV ","xpxpvvvv"]}`)})
	if e != nil {
		t.Fatal(e)
	}
	s := v.(Sudoku)
	if len(s.CustomTables) != 2 || s.CustomTables[1] != "xpxpvvvv" {
		t.Fatal("normalization")
	}
}
func FuzzMaskConfig(f *testing.F) {
	for _, s := range []string{`{"tcp":[{"type":"sudoku","settings":{"password":"synthetic"}}]}`, `{"tcp":[{"type":"fragment","settings":{"length":8}}]}`, `{"tcp":[{"type":"header-custom","settings":{"clients":[[{"type":"hex","packet":"41"}]]}}]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 16384 {
			return
		}
		var c Config
		_ = json.Unmarshal(b, &c)
	})
}
func FuzzRange(f *testing.F) {
	f.Add("1-8")
	f.Add("0")
	f.Add("4294967296")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 128 {
			return
		}
		r, e := ParseRange(s, 65535)
		if e == nil && !r.Valid(65535) {
			t.Fatal(r)
		}
	})
}
