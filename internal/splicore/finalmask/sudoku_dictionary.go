package finalmask

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"math/rand"
	"slices"
	"sync"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
)

type sudokuDictionary struct {
	alphabet     *sudokuAlphabet
	choices      [256][][4]byte
	observations map[uint64]byte
}

// Three rows are chosen from permutations. Each column determines its missing
// fourth-row digit. This enumerates boards without a cell-search solver.
func sudokuBoards() [][16]byte {
	var rows [][4]byte
	for a := byte(1); a <= 4; a++ {
		for b := byte(1); b <= 4; b++ {
			for c := byte(1); c <= 4; c++ {
				if a != b && a != c && b != c {
					rows = append(rows, [4]byte{a, b, c, 10 - a - b - c})
				}
			}
		}
	}
	var result [][16]byte
	for _, top := range rows {
		for _, second := range rows {
			if top[0] == second[0] || top[1] == second[1] || top[2] == second[2] || top[3] == second[3] {
				continue
			}
			if top[0] == second[1] || top[1] == second[0] || top[2] == second[3] || top[3] == second[2] {
				continue
			}
			for _, third := range rows {
				var board [16]byte
				copy(board[:4], top[:])
				copy(board[4:8], second[:])
				copy(board[8:12], third[:])
				valid := true
				for col := 0; col < 4; col++ {
					if third[col] == top[col] || third[col] == second[col] {
						valid = false
						break
					}
					board[12+col] = 10 - top[col] - second[col] - third[col]
				}
				if !valid || board[12] == board[13] || board[12] == board[14] || board[12] == board[15] || board[13] == board[14] || board[13] == board[15] || board[14] == board[15] {
					continue
				}
				if third[0] == board[13] || third[1] == board[12] || third[2] == board[15] || third[3] == board[14] {
					continue
				}
				result = append(result, board)
			}
		}
	}
	slices.SortFunc(result, func(a, b [16]byte) int { return bytes.Compare(a[:], b[:]) })
	return result
}

// Matching-board bitsets turn a four-clue uniqueness check into intersections.
// The resulting logical choices are independent of all wire alphabets.
var sudokuChoices = sync.OnceValue(func() [][][4]byte {
	boards := sudokuBoards()
	var matching [16][5][5]uint64
	for i, board := range boards {
		for cell, digit := range board {
			matching[cell][digit][i/64] |= uint64(1) << (i % 64)
		}
	}
	choices := make([][][4]byte, len(boards))
	for a := 0; a < 13; a++ {
		for b := a + 1; b < 14; b++ {
			for c := b + 1; c < 15; c++ {
				for d := c + 1; d < 16; d++ {
					for i, board := range boards {
						count := 0
						for w := 0; w < 5; w++ {
							count += bits.OnesCount64(matching[a][board[a]][w] & matching[b][board[b]][w] & matching[c][board[c]][w] & matching[d][board[d]][w])
							if count > 1 {
								break
							}
						}
						if count != 1 {
							continue
						}
						clues := [4]byte{byte(a) | (board[a]-1)<<4, byte(b) | (board[b]-1)<<4, byte(c) | (board[c]-1)<<4, byte(d) | (board[d]-1)<<4}
						slices.Sort(clues[:])
						choices[i] = append(choices[i], clues)
					}
				}
			}
		}
	}
	return choices
})

// A three-bit digit slot per cell represents a set of observations, independent
// of clue order. Repeated cells are rejected instead of silently overwriting.
func sudokuObservation(clues [4]byte) (uint64, bool) {
	var key uint64
	for _, g := range clues {
		shift := uint(g&15) * 3
		if key&(7<<shift) != 0 {
			return 0, false
		}
		key |= uint64(1+(g>>4)) << shift
	}
	return key, true
}

func buildSudokuDictionaries(s cfg.Sudoku) ([]*sudokuDictionary, error) {
	all := sudokuChoices()
	order := make([]int, len(all))
	for i := range order {
		order[i] = i
	}
	hash := sha256.Sum256([]byte(s.Password))
	random := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(hash[:8]))))
	random.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	patterns := s.CustomTables
	if len(patterns) == 0 {
		patterns = []string{s.CustomTable}
	}
	var result []*sudokuDictionary
	for _, pattern := range patterns {
		alphabet, err := makeSudokuAlphabet(s.ASCII, pattern)
		if err != nil {
			return nil, err
		}
		d := &sudokuDictionary{alphabet: alphabet, observations: make(map[uint64]byte)}
		for value, index := range order[:256] {
			d.choices[value] = all[index]
			for _, clues := range all[index] {
				key, _ := sudokuObservation(clues)
				d.observations[key] = byte(value)
			}
		}
		result = append(result, d)
	}
	return result, nil
}
