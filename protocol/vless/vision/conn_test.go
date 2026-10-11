package vision

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	"github.com/ike-sh/Splicore/internal/splicore/finalmask"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/vless/backend"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
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
	a.SetDeadline(time.Now().Add(15 * time.Second))
	b.SetDeadline(time.Now().Add(15 * time.Second))
	return a, b
}
func TestRealTLSDirectTransition(t *testing.T) {
	for _, masked := range []bool{false, true} {
		t.Run(map[bool]string{false: "socket", true: "sudoku-underlay"}[masked], func(t *testing.T) {
			a, b := tcpPair(t)
			if masked {
				m := &cfg.Config{TCP: []cfg.Mask{{Type: "sudoku", Settings: json.RawMessage(`{"password":"synthetic"}`)}}}
				var e error
				a, e = finalmask.Wrap(a, m, false)
				if e != nil {
					t.Fatal(e)
				}
				b, e = finalmask.Wrap(b, m, true)
				if e != nil {
					t.Fatal(e)
				}
			}
			material := testkit.TLSForName(t, "inner.synthetic.test")
			cert, _ := os.ReadFile(material.CertificateFile)
			key, _ := os.ReadFile(material.PrivateKeyFile)
			pair, e := tls.X509KeyPair(cert, key)
			clear(key)
			if e != nil {
				t.Fatal(e)
			}
			outerC := tls.Client(LimitRecords(a), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
			outerS := tls.Server(LimitRecords(b), &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
			done := make(chan error, 1)
			go func() { done <- outerS.Handshake() }()
			if e = outerC.Handshake(); e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			pc, ps := BufferRecords(outerC), BufferRecords(outerS)
			id := [16]byte{1, 2, 3}
			vc := New(&backend.Conn{Conn: pc}, pc, a, id)
			vs := New(&backend.Conn{Conn: ps, Server: true}, ps, b, id)
			innerC := tls.Client(vc, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
			innerS := tls.Server(vs, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
			payload := bytes.Repeat([]byte("inner TLS exact bytes"), 10000)
			go func() {
				if e := innerS.Handshake(); e != nil {
					done <- e
					return
				}
				got := make([]byte, len(payload))
				_, e := io.ReadFull(innerS, got)
				if e == nil && !bytes.Equal(got, payload) {
					e = ErrFrame
				}
				if e == nil {
					_, e = innerS.Write(got)
				}
				done <- e
			}()
			if e = innerC.Handshake(); e != nil {
				t.Fatal(e)
			}
			if _, e = innerC.Write(payload); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, len(payload))
			if _, e = io.ReadFull(innerC, got); e != nil || !bytes.Equal(got, payload) {
				t.Fatal("application payload", e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			r, w := vc.DirectState()
			sr, sw := vs.DirectState()
			if !r || !w || !sr || !sw {
				t.Fatalf("direct state %v %v %v %v", r, w, sr, sw)
			}
		})
	}
}

type testConn struct{ *bytes.Reader }

func (c testConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c testConn) Close() error                     { return nil }
func (c testConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c testConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c testConn) SetDeadline(time.Time) error      { return nil }
func (c testConn) SetReadDeadline(time.Time) error  { return nil }
func (c testConn) SetWriteDeadline(time.Time) error { return nil }
func frame(id bool, cmd byte, content, pad []byte) []byte {
	var b []byte
	if id {
		b = make([]byte, 16)
	}
	b = append(b, cmd)
	b = binary.BigEndian.AppendUint16(b, uint16(len(content)))
	b = binary.BigEndian.AppendUint16(b, uint16(len(pad)))
	b = append(b, content...)
	return append(b, pad...)
}
func TestFramesPartialCoalesced(t *testing.T) {
	p := append(frame(true, 0, nil, []byte{1}), frame(false, 0, []byte("hello"), nil)...)
	p = append(p, frame(false, 1, []byte("world"), []byte{3, 4})...)
	p = append(p, []byte("tail")...)
	raw := testConn{bytes.NewReader(p)}
	plain := BufferRecords(raw)
	c := New(plain, plain, raw, [16]byte{})
	var got []byte
	for {
		var b [1]byte
		n, e := c.Read(b[:])
		got = append(got, b[:n]...)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if string(got) != "helloworldtail" {
		t.Fatal(string(got))
	}
}
func TestMalformedVision(t *testing.T) {
	for _, b := range [][]byte{frame(true, 9, nil, nil), frame(true, 0, []byte("truncated"), nil)[:20], append(bytes.Repeat([]byte{1}, 16), frame(false, 0, nil, nil)...)} {
		raw := testConn{bytes.NewReader(b)}
		plain := BufferRecords(raw)
		c := New(plain, plain, raw, [16]byte{})
		if _, e := io.ReadAll(c); e == nil {
			t.Fatal("accepted malformed")
		}
	}
}

type shortWriter struct {
	testConn
	count int
	err   error
	calls int
}

func (w *shortWriter) Write(p []byte) (int, error) { w.calls++; return min(w.count, len(p)), w.err }
func TestVisionShortWriteAndTerminalFailure(t *testing.T) {
	failed := errors.New("synthetic short write")
	for _, tc := range []struct {
		count, want int
		err         error
	}{{0, 0, nil}, {20, 0, failed}, {24, 3, failed}, {27, 6, failed}, {24, 3, nil}} {
		w := &shortWriter{testConn: testConn{bytes.NewReader(nil)}, count: tc.count, err: tc.err}
		plain := BufferRecords(w)
		c := New(w, plain, w, [16]byte{})
		if n, e := c.Write([]byte("abcdef")); n != tc.want || e == nil {
			t.Fatal("accepted payload prefix", n, e)
		}
		if n, e := c.Write([]byte("again")); n != 0 || e == nil || w.calls != 1 {
			t.Fatal("failed frame replayed", n, e)
		}
	}
}
func TestRecordLimitNoReadAhead(t *testing.T) {
	b := []byte{23, 3, 3, 0, 2, 10, 11, 99}
	raw := testConn{bytes.NewReader(b)}
	r := LimitRecords(raw)
	got := make([]byte, 64)
	n, e := r.Read(got)
	if n != 5 || e != nil {
		t.Fatal(n, e)
	}
	n, e = r.Read(got)
	if n != 2 || e != nil || raw.Len() != 1 {
		t.Fatal("read ahead", n, e)
	}
}
func FuzzVisionFrames(f *testing.F) {
	f.Add(frame(true, 1, []byte("hello"), []byte{1, 2}))
	f.Add(frame(true, 9, nil, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		raw := testConn{bytes.NewReader(b)}
		plain := BufferRecords(raw)
		c := New(plain, plain, raw, [16]byte{})
		_, _ = io.Copy(io.Discard, io.LimitReader(c, 65537))
	})
}
