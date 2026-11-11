package finalmask

import (
	"bytes"
	"encoding/hex"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	"math/rand/v2"
	"testing"
)

// These classic uplink vectors were produced by unmodified Xray v26.9.9
// table.go and codec.go, using the same test-only ChaCha8 seed.
func TestSudokuPinnedVectors(t *testing.T) {
	payload := []byte{0, 1, 17, 127, 128, 254, 255}
	for _, tc := range []struct {
		name, ascii string
		custom      []string
		pad         int
		wire        string
	}{
		{"entropy", "prefer_entropy", nil, 0, "6a61440949250e620e612920262b0c676b00224920426b29630e4825"},
		{"ascii", "prefer_ascii", nil, 100, "2a3071226d2c7c3d4639297d254e31532460203c59307a2764237734216f3c4331643378233b553a63267b3f4d223543356f3f762d4d2c3e5b3c662340247d3e"},
		{"multi", "prefer_entropy", []string{"xxppvvvv", "xpxpvvvv"}, 100, "4f9ff1b7ed6efcabc67973fd67aecfb3d7e07e8fd977fa9ee45ff797d5ef7da37ae49bf87f4fd5abe375fb9ecdd96fa39bef97f63ead777bdb57e69dc0b5fd7b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.custom) == 0 {
				tc.custom = []string{""}
			}
			tables, e := cachedTables(cfg.Sudoku{Password: "synthetic-vector", ASCII: tc.ascii, CustomTables: tc.custom})
			if e != nil {
				t.Fatal(e)
			}
			c := newSudokuUplink(tables, tc.pad, tc.pad)
			c.random = rand.New(rand.NewChaCha8([32]byte{1, 2, 3, 4}))
			got, e := c.encode(payload)
			want, _ := hex.DecodeString(tc.wire)
			if e != nil || !bytes.Equal(got, want) {
				t.Fatalf("vector %x, %v", got, e)
			}
			decoder := sudokuConn{server: true, tables: tables}
			for _, v := range want {
				if e := decoder.decode([]byte{v}); e != nil {
					t.Fatal(e)
				}
			}
			if !bytes.Equal(decoder.pending, payload) {
				t.Fatal("vector decode")
			}
		})
	}
}
