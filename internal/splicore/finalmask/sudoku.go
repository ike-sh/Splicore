package finalmask

import (
	"encoding/json"
	"errors"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	"io"
	"sync"
)

// A bounded cache shares immutable tables only. Decoder indices, padding RNGs
// and all stream buffers belong to each connection and direction.
var tablesCache struct {
	sync.Mutex
	keys   []string
	tables map[string][]*sudokuDictionary
}

func cachedTables(s cfg.Sudoku) ([]*sudokuDictionary, error) {
	b, _ := json.Marshal(s)
	key := string(b)
	tablesCache.Lock()
	defer tablesCache.Unlock()
	if t := tablesCache.tables[key]; t != nil {
		return t, nil
	}
	t, e := buildSudokuDictionaries(s)
	if e != nil {
		return nil, e
	}
	if tablesCache.tables == nil {
		tablesCache.tables = make(map[string][]*sudokuDictionary)
	}
	if len(tablesCache.keys) == 16 {
		delete(tablesCache.tables, tablesCache.keys[0])
		tablesCache.keys = tablesCache.keys[1:]
	}
	tablesCache.keys = append(tablesCache.keys, key)
	tablesCache.tables[key] = t
	return t, nil
}

type sudokuConn struct {
	*base
	server            bool
	tables            []*sudokuDictionary
	enc               *sudokuUplink
	rmu, wmu          sync.Mutex
	pending           []byte
	hint              []byte
	rindex, windex    int
	bits              uint32
	nbits             int
	idle              int
	readErr, writeErr error
}

func newSudoku(b *base, s cfg.Sudoku, server bool) (*sudokuConn, error) {
	t, e := cachedTables(s)
	if e != nil {
		return nil, e
	}
	return &sudokuConn{base: b, server: server, tables: t, enc: newSudokuUplink(t, s.PaddingMin, s.PaddingMax)}, nil
}
func (c *sudokuConn) packed(p []byte) []byte {
	var bits uint32
	count := 0
	out := make([]byte, 0, len(p)*3+8)
	pad := func(l *sudokuAlphabet) {
		if c.enc.addNoise() {
			pool := l.noise
			idx := c.enc.random.IntN(len(pool))
			for pool[idx] == l.reset {
				idx = c.enc.random.IntN(len(pool))
			}
			out = append(out, pool[idx])
		}
	}
	group := func(v byte) {
		l := c.tables[c.windex].alphabet
		pad(l)
		out = append(out, l.symbols[v])
		c.windex = (c.windex + 1) % len(c.tables)
	}
	for _, b := range p {
		bits = bits<<8 | uint32(b)
		count += 8
		for count >= 6 {
			count -= 6
			group(byte(bits>>count) & 63)
			bits &= (1 << count) - 1
		}
	}
	if count > 0 {
		group(byte(bits << (6 - count)))
		out = append(out, c.tables[c.windex].alphabet.reset)
	}
	pad(c.tables[c.windex].alphabet)
	return out
}
func (c *sudokuConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	sent := 0
	for len(p) > 0 {
		n := min(len(p), 16384)
		var wire []byte
		var e error
		if c.server {
			wire = c.packed(p[:n])
		} else {
			wire, e = c.enc.encode(p[:n])
		}
		if e == nil {
			e = writeFull(c.Conn, wire)
		}
		if e != nil {
			c.writeErr = e
			return sent, e
		}
		sent += n
		p = p[n:]
	}
	return sent, nil
}
func (c *sudokuConn) decode(p []byte) error {
	for _, b := range p {
		t := c.tables[c.rindex]
		if t.alphabet.groups[b] < 0 {
			c.idle++
			if c.idle > 1<<20 {
				return errors.New("Sudoku padding progress bound exceeded")
			}
			if !c.server && b == t.alphabet.reset {
				c.bits = 0
				c.nbits = 0
			}
			continue
		}
		c.idle = 0
		if c.server {
			if t.alphabet.clues[b] < 0 {
				return errors.New("invalid Sudoku tuple")
			}
			c.hint = append(c.hint, byte(t.alphabet.clues[b]))
			if len(c.hint) < 4 {
				continue
			}
			key, distinct := sudokuObservation([4]byte(c.hint))
			v, ok := t.observations[key]
			if !ok || !distinct {
				return errors.New("invalid Sudoku tuple")
			}
			c.pending = append(c.pending, v)
			c.hint = c.hint[:0]
		} else {
			g := t.alphabet.groups[b]
			ok := g >= 0
			if !ok {
				return errors.New("invalid Sudoku group")
			}
			c.bits = c.bits<<6 | uint32(g)
			c.nbits += 6
			if c.nbits >= 8 {
				c.nbits -= 8
				c.pending = append(c.pending, byte(c.bits>>c.nbits))
				c.bits &= (1 << c.nbits) - 1
			}
		}
		c.rindex = (c.rindex + 1) % len(c.tables)
	}
	return nil
}
func (c *sudokuConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 && c.readErr == nil {
		var buf [32768]byte
		n, e := c.Conn.Read(buf[:])
		if n > 0 {
			if de := c.decode(buf[:n]); de != nil {
				c.readErr = de
			}
		}
		if e != nil && c.readErr == nil {
			if e == io.EOF && (len(c.hint) > 0 || c.nbits > 0) {
				e = io.ErrUnexpectedEOF
			}
			c.readErr = e
		}
		if n == 0 && e == nil {
			c.readErr = io.ErrNoProgress
		}
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return 0, c.readErr
}
