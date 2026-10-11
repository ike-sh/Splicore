package finalmask

import (
	"math/bits"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
)

// An alphabet separates wire glyphs from the logical cell/digit observations.
// Arrays make the classic canonicality rule distinct from packed aliases.
type sudokuAlphabet struct {
	symbols [64]byte
	groups  [256]int16
	clues   [256]int16
	noise   []byte
	reset   byte
}

func makeSudokuAlphabet(ascii, pattern string) (*sudokuAlphabet, error) {
	a := &sudokuAlphabet{}
	for i := range a.groups {
		a.groups[i], a.clues[i] = -1, -1
	}
	var fixed byte
	var positions []uint
	if pattern != "" {
		if len(pattern) != 8 {
			return nil, cfg.ErrConfig
		}
		for i, ch := range pattern {
			if ch == 'x' {
				fixed |= 1 << (7 - i)
			}
		}
		for _, ch := range []rune{'p', 'v'} {
			for i, p := range pattern {
				if p == ch {
					positions = append(positions, uint(7-i))
				}
			}
		}
		if bits.OnesCount8(fixed) != 2 || len(positions) != 6 {
			return nil, cfg.ErrConfig
		}
	}
	for g := 0; g < 64; g++ {
		var symbol byte
		switch {
		case ascii == "prefer_ascii":
			symbol = 0x40 | byte(g)
			if symbol == 0x7f {
				symbol = '\n'
			}
		case pattern != "":
			symbol = fixed
			for j, pos := range positions {
				symbol |= byte((g>>(5-j))&1) << pos
			}
		default:
			symbol = byte((g&0x30)<<1 | (g & 0x0f))
		}
		a.symbols[g] = symbol
		a.clues[symbol] = int16(g)
		a.groups[symbol] = int16(g)
	}
	switch {
	case ascii == "prefer_ascii":
		for b := 0; b < 256; b++ {
			if b&0x40 != 0 {
				a.groups[b] = int16(b & 63)
			}
		}
		for b := 0x20; b <= 0x3f; b++ {
			a.noise = append(a.noise, byte(b))
		}
		a.reset = 0x3f
	case pattern != "":
		for b := 0; b < 256; b++ {
			if bits.OnesCount8(byte(b)&fixed) == 1 && bits.OnesCount8(byte(b)) >= 5 {
				a.noise = append(a.noise, byte(b))
			}
		}
		a.reset = a.noise[0]
	default:
		for i := 0; i < 8; i++ {
			a.noise = append(a.noise, byte(0x80+i), byte(0x10+i))
		}
		a.reset = 0x80
	}
	return a, nil
}
