package finalmask

import (
	"bytes"
	"encoding/json"
	"errors"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func mask(typ, s string) cfg.Mask { return cfg.Mask{Type: typ, Settings: json.RawMessage(s)} }
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ch := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); ch <- c }()
	a, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	b := <-ch
	l.Close()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
func TestMaskDuplexHalfClose(t *testing.T) {
	h := mask("header-custom", `{"clients":[[{"type":"str","packet":"HELLO"},{"rand":3,"randRange":"1-7"}]],"servers":[[{"type":"hex","packet":"4142"}]]}`)
	f := mask("fragment", `{"lengths":[0,"13-19"],"delays":[0],"maxSplit":64}`)
	s := mask("sudoku", `{"password":"synthetic","paddingMin":50,"paddingMax":100,"customTables":["xxppvvvv","xpxpvvvv"]}`)
	for name, ms := range map[string][]cfg.Mask{"header": {h}, "fragment": {f}, "sudoku": {s}, "fragment-sudoku": {f, s}, "sudoku-fragment": {s, f}, "header-sudoku-fragment": {h, s, f}} {
		t.Run(name, func(t *testing.T) {
			a, b := tcpPair(t)
			c, e := Wrap(a, &cfg.Config{TCP: ms}, false)
			if e != nil {
				t.Fatal(e)
			}
			d, e := Wrap(b, &cfg.Config{TCP: ms}, true)
			if e != nil {
				t.Fatal(e)
			}
			c.SetDeadline(time.Now().Add(10 * time.Second))
			d.SetDeadline(time.Now().Add(10 * time.Second))
			p := bytes.Repeat([]byte{0, 1, 17, 255}, 65537)
			reply := []byte("drained-reply")
			done := make(chan error, 1)
			go func() {
				got, e := io.ReadAll(d)
				if e == nil && !bytes.Equal(got, p) {
					e = errors.New("upload mismatch")
				}
				if e == nil {
					_, e = d.Write(reply)
				}
				if e == nil {
					e = d.(interface{ CloseWrite() error }).CloseWrite()
				}
				done <- e
			}()
			if _, e = c.Write(nil); e != nil {
				t.Fatal(e)
			}
			for off := 0; off < len(p); {
				n := min(31, len(p)-off)
				if _, e = c.Write(p[off : off+n]); e != nil {
					t.Fatal(e)
				}
				off += n
			}
			if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(c)
			if e != nil || !bytes.Equal(got, reply) {
				t.Fatal("reply", e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

type memoryConn struct {
	bytes.Buffer
	writes [][]byte
	half   int
}

type limitedConn struct {
	memoryConn
	remaining int
	err       error
}

func (c *limitedConn) Write(p []byte) (int, error) {
	n := min(len(p), c.remaining)
	c.remaining -= n
	c.Buffer.Write(p[:n])
	if n < len(p) {
		return n, c.err
	}
	return n, nil
}
func TestFragmentPartialWriteProgress(t *testing.T) {
	failure := errors.New("synthetic write failure")
	for _, tc := range []struct {
		name, settings string
		payload        []byte
		limit, want    int
	}{
		{"stream", `{"length":3,"delay":0}`, []byte("abcdefgh"), 5, 5},
		{"tls-merged", `{"packets":"tlshello","length":2,"delay":0}`, []byte{22, 3, 3, 0, 5, 1, 2, 3, 4, 5}, 12, 7},
		{"tls-delayed", `{"packets":"tlshello","length":2,"delay":1}`, []byte{22, 3, 3, 0, 5, 1, 2, 3, 4, 5}, 12, 7},
		{"tls-tail", `{"packets":"tlshello","length":2,"delay":0}`, []byte{22, 3, 3, 0, 5, 1, 2, 3, 4, 5, 6, 7, 8}, 21, 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &limitedConn{remaining: tc.limit, err: failure}
			c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{mask("fragment", tc.settings)}}, false)
			if e != nil {
				t.Fatal(e)
			}
			if n, e := c.Write(tc.payload); n != tc.want || !errors.Is(e, failure) {
				t.Fatalf("progress %d, %v; want %d", n, e, tc.want)
			}
			if n, e := c.Write(tc.payload); n != 0 || !errors.Is(e, failure) {
				t.Fatal("failed transformation reused", n, e)
			}
		})
	}
	for _, noProgress := range []bool{false, true} {
		raw := &limitedConn{remaining: 0, err: nil}
		settings := `{"length":1,"delay":30000}`
		if !noProgress {
			raw.remaining = 1
		}
		c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{mask("fragment", settings)}}, false)
		if e != nil {
			t.Fatal(e)
		}
		c.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
		n, e := c.Write([]byte{1, 2})
		if noProgress {
			if n != 0 || !errors.Is(e, io.ErrNoProgress) {
				t.Fatal(n, e)
			}
		} else if n != 1 || !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatal(n, e)
		}
	}
}

func (c *memoryConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(b))
	return c.Buffer.Write(b)
}
func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) CloseWrite() error                { c.half++; return nil }
func (c *memoryConn) CloseRead() error                 { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }
func TestConfiguredOrderAndTLSBytes(t *testing.T) {
	raw := &memoryConn{}
	c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{mask("header-custom", `{"clients":[[{"type":"str","packet":"A"}]]}`), mask("header-custom", `{"clients":[[{"type":"str","packet":"B"}]]}`), mask("header-custom", `{"clients":[[{"type":"str","packet":"C"}]]}`)}}, false)
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte{22, 3, 3, 0, 1, 42}
	c.Write(payload)
	if !bytes.Equal(raw.Bytes(), append([]byte("CBA"), payload...)) {
		t.Fatal("configured order", raw.Bytes())
	}
	if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil || raw.half != 1 {
		t.Fatal("capability")
	}
}
func TestFragmentTLSHelloAndSplitBounds(t *testing.T) {
	raw := &memoryConn{}
	c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{mask("fragment", `{"packets":"tlshello","lengths":[0,2],"delays":[0],"maxSplit":4}`)}}, false)
	if e != nil {
		t.Fatal(e)
	}
	p := []byte{22, 3, 1, 0, 5, 1, 2, 3, 4, 5, 99}
	if _, e = c.Write(p); e != nil {
		t.Fatal(e)
	}
	got := raw.Bytes()
	var body []byte
	for len(got) > 1 {
		n := int(got[3])<<8 | int(got[4])
		body = append(body, got[5:5+n]...)
		got = got[5+n:]
	}
	if !bytes.Equal(body, p[5:10]) || len(got) != 1 || got[0] != 99 {
		t.Fatal("TLS record transformation")
	}
}
func TestFragmentOpaqueSudokuAndNonTLS(t *testing.T) {
	f := mask("fragment", `{"packets":"tlshello","length":2,"delay":0}`)
	raw := &memoryConn{}
	c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{mask("sudoku", `{"password":"synthetic"}`), f}}, false)
	if e != nil {
		t.Fatal(e)
	}
	outer := c.(*sudokuConn).Conn.(*fragmentConn)
	// Even a TLS-looking prefix must be opaque after an inner Sudoku encoder.
	p := []byte{22, 3, 3, 0, 5, 1, 2, 3, 4, 5}
	if n, e := outer.Write(p); n != len(p) || e != nil || !bytes.Equal(raw.Bytes(), p) {
		t.Fatal("encoded bytes rewritten", n, e)
	}
	for _, p := range [][]byte{{22, 0, 0, 0, 5, 1, 2, 3, 4, 5}, {22, 3, 3, 0, 5, 2, 2, 3, 4, 5}} {
		raw := &memoryConn{}
		c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{f}}, false)
		if e != nil {
			t.Fatal(e)
		}
		c.Write(p)
		if !bytes.Equal(raw.Bytes(), p) {
			t.Fatal("non-ClientHello rewritten")
		}
	}
}
func TestDelayDeadlineClose(t *testing.T) {
	for _, closeIt := range []bool{false, true} {
		raw := &memoryConn{}
		c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{mask("fragment", `{"length":1,"delay":30000}`)}}, false)
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { _, e := c.Write([]byte{1, 2}); done <- e }()
		if closeIt {
			c.Close()
		} else {
			c.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
		}
		select {
		case e := <-done:
			if closeIt && !errors.Is(e, net.ErrClosed) || !closeIt && !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal(e)
			}
		case <-time.After(time.Second):
			t.Fatal("uncancellable delay")
		}
	}
}
func TestSudokuTruncationAndInvalidTuple(t *testing.T) {
	for _, p := range [][]byte{{0}, {0, 0, 0, 0}, bytes.Repeat([]byte{0x80}, (1<<20)+1)} {
		raw := &memoryConn{}
		raw.Buffer.Write(p)
		c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{mask("sudoku", `{"password":"synthetic"}`)}}, true)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.ReadAll(c); e == nil {
			t.Fatal("accepted malformed stream")
		}
	}
}

func TestSudokuWrongPasswordDoesNotFallback(t *testing.T) {
	v, e := cfg.Decode(mask("sudoku", `{"password":"synthetic-right","paddingMin":0,"paddingMax":0}`))
	if e != nil {
		t.Fatal(e)
	}
	tables, e := cachedTables(v.(cfg.Sudoku))
	if e != nil {
		t.Fatal(e)
	}
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	wire, e := newSudokuUplink(tables, 0, 0).encode(payload)
	if e != nil {
		t.Fatal(e)
	}
	raw := &memoryConn{}
	raw.Buffer.Write(wire)
	c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{mask("sudoku", `{"password":"synthetic-wrong"}`)}}, true)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(c)
	if e == nil || bytes.Equal(got, payload) || bytes.Equal(got, wire) {
		t.Fatal("wrong-password uplink accepted or bypassed")
	}
}

func TestHeaderErrorSequence(t *testing.T) {
	raw := &memoryConn{}
	raw.Buffer.WriteString("BAD")
	c, e := Wrap(raw, &cfg.Config{TCP: []cfg.Mask{mask("header-custom", `{"clients":[[{"type":"str","packet":"ABC"}]],"errors":[[{"type":"str","packet":"ERR"}]]}`)}}, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := c.Read(make([]byte, 1)); e == nil {
		t.Fatal("bad header accepted")
	}
	if len(raw.writes) != 1 || string(raw.writes[0]) != "ERR" {
		t.Fatal("error sequence missing")
	}
	if _, e := c.Write([]byte("payload")); e == nil || len(raw.writes) != 1 {
		t.Fatal("handshake failure replayed")
	}
}
func FuzzSudokuDecoder(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{128})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 32768 {
			return
		}
		s := cfg.Sudoku{Password: "synthetic", ASCII: "prefer_entropy", CustomTables: []string{""}}
		tables, e := cachedTables(s)
		if e != nil {
			t.Fatal(e)
		}
		for _, server := range []bool{false, true} {
			c := sudokuConn{tables: tables, server: server}
			_ = c.decode(p)
			if len(c.pending) > len(p) || len(c.hint) > 4 {
				t.Fatal("bounds")
			}
		}
	})
}
