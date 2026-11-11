package httpproxy

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestPhase20HTTPBoundsAndSmuggling(t *testing.T) {
	for _, a := range []string{"example.test:80", "127.0.0.1:443", "[::1]:443"} {
		if _, e := Authority(a); e != nil {
			t.Fatal(e)
		}
	}
	for _, a := range []string{"example.test", "a:0", "a:+80", "a:65536", "a:80/path", "u@a:80", "::1:80", "a:80\r\nX: y"} {
		if _, e := Authority(a); e == nil {
			t.Fatal("authority accepted")
		}
	}
	for _, raw := range []string{
		"CONNECT a:80 HTTP/1.1\r\nHost: b:80\r\n\r\n",
		"GET http://a/ HTTP/1.1\r\nHost: b\r\n\r\n",
		"GET http://a/ HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
		"POST http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
		"POST http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
		"CONNECT a:80 HTTP/1.1\r\nHost: a:80\r\nProxy-Authorization: Basic YTpi\r\nProxy-Authorization: Basic YTpi\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n\r\n", "GE(T http://a/ HTTP/1.1\r\nHost: a\r\n\r\n",
		"GET http://u:p@a/ HTTP/1.1\r\nHost: a\r\n\r\n", "GET http://a/ HTTP/1.1\r\nX: " + strings.Repeat("x", MaxLine) + "\r\n\r\n",
	} {
		if _, _, e := ReadRequest(bufio.NewReader(strings.NewReader(raw))); e == nil {
			t.Fatal("unsafe request accepted")
		}
	}
	r := bufio.NewReader(strings.NewReader("POST http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc"))
	req, _, e := ReadRequest(r)
	if e != nil {
		t.Fatal(e)
	}
	p := make([]byte, 3)
	n, e := req.Body.Read(p)
	if n != 3 || string(p) != "abc" {
		t.Fatal("stream body", e)
	}
	for _, b := range []string{"", "Bearer token", "Basic !!!", "Basic YQ=="} {
		if _, e := Basic(b); e == nil {
			t.Fatal("bad auth accepted")
		}
	}
}
func TestPhase20DetectionDoesNotConsume(t *testing.T) {
	for _, b := range [][]byte{{5, 1, 0}, []byte("CONNECT a:80 HTTP/1.1\r\n"), []byte("GET http://a/ HTTP/1.1\r\n")} {
		r := bufio.NewReader(bytes.NewReader(b))
		if _, e := Detect(r); e != nil {
			t.Fatal(e)
		}
		p, _ := r.Peek(len(b))
		if !bytes.Equal(b, p) {
			t.Fatal("consumed sniff bytes")
		}
	}
}
func FuzzAuthority(f *testing.F) {
	f.Add("[::1]:443")
	f.Add("a:80")
	f.Fuzz(func(t *testing.T, s string) {
		e, err := Authority(s)
		if err == nil && e.Validate() != nil {
			t.Fatal("invalid accepted")
		}
	})
}
func FuzzMixedDetection(f *testing.F) {
	f.Add([]byte{5})
	f.Add([]byte("CONNECT "))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bufio.NewReader(bytes.NewReader(b))
		_, _ = Detect(r)
		if r.Buffered() > 4096 {
			t.Fatal("unbounded sniff")
		}
	})
}
