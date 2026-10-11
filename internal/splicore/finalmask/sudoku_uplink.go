package finalmask

import (
	"crypto/rand"
	random "math/rand/v2"
)

type sudokuUplink struct {
	dictionaries []*sudokuDictionary
	random       *random.Rand
	padding      int
	cursor       int
}

func newSudokuUplink(d []*sudokuDictionary, low, high int) *sudokuUplink {
	var seed [32]byte
	rand.Read(seed[:])
	r := random.New(random.NewChaCha8(seed))
	padding := low
	if high > low {
		padding += r.IntN(high - low + 1)
	}
	return &sudokuUplink{dictionaries: d, random: r, padding: padding}
}

func (u *sudokuUplink) addNoise() bool {
	return u.padding == 100 || u.padding > 0 && u.random.IntN(100) < u.padding
}

func (u *sudokuUplink) encode(p []byte) ([]byte, error) {
	out := make([]byte, 0, len(p)*4)
	noise := func(a *sudokuAlphabet) {
		if u.addNoise() {
			out = append(out, a.noise[u.random.IntN(len(a.noise))])
		}
	}
	for _, b := range p {
		d := u.dictionaries[u.cursor]
		noise(d.alphabet)
		clues := d.choices[b][u.random.IntN(len(d.choices[b]))]
		rank := u.random.IntN(24)
		// Factoradic unranking yields the lexicographic permutation directly.
		remaining := []int{0, 1, 2, 3}
		for _, divisor := range []int{6, 2, 1, 1} {
			index := rank / divisor
			rank %= divisor
			noise(d.alphabet)
			out = append(out, d.alphabet.symbols[clues[remaining[index]]])
			remaining = append(remaining[:index], remaining[index+1:]...)
		}
		u.cursor = (u.cursor + 1) % len(u.dictionaries)
	}
	noise(u.dictionaries[u.cursor].alphabet)
	return out, nil
}
