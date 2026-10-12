package wire

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHTTPFragmentedHeaderAndCoalescedPayload(t *testing.T) {
	for _, server := range []bool{true, false} {
		t.Run(map[bool]string{true: "request", false: "response"}[server], func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = a.SetDeadline(time.Now().Add(time.Second))
			var c net.Conn = HTTPClient(a, "test.example", "/custom?test=1")
			header := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n"
			if server {
				c = HTTPServer(a)
				header = "GET /custom?test=1 HTTP/1.1\r\nHost: test.example\r\nContent-Length: 4\r\n\r\n"
			}
			payload := []byte{0, 255, 7, 8}
			done := make(chan error, 1)
			go func() {
				for _, p := range [][]byte{[]byte(header[:3]), []byte(header[3 : len(header)-2]), append([]byte(header[len(header)-2:]), payload...)} {
					if _, e := b.Write(p); e != nil {
						done <- e
						return
					}
				}
				done <- nil
			}()
			got := make([]byte, 4)
			if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(got, payload) {
				t.Fatal(got, e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestHTTPHostURISingleHeader(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(time.Second))
	c := HTTPClient(a, "cover.example", "/resource?x=1")
	done := make(chan error, 1)
	go func() {
		_, e := c.Write([]byte("first"))
		if e == nil {
			_, e = c.Write([]byte("second"))
		}
		done <- e
	}()
	r := bufio.NewReader(b)
	var header strings.Builder
	for {
		line, e := r.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		header.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	if !strings.HasPrefix(header.String(), "GET /resource?x=1 HTTP/1.1\r\nHost: cover.example\r\n") || !strings.Contains(header.String(), "Content-Length: 5\r\n") {
		t.Fatal(header.String())
	}
	got := make([]byte, 11)
	if _, e := io.ReadFull(r, got); e != nil || string(got) != "firstsecond" {
		t.Fatal(string(got), e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestHTTPMalformedBoundedAndDeadline(t *testing.T) {
	for _, input := range []string{"POST / HTTP/1.1\r\n\r\n", "GET / HTTP/1.1\r\nBad Header\r\n\r\n", strings.Repeat("x", 8192)} {
		a, b := net.Pipe()
		_ = a.SetDeadline(time.Now().Add(time.Second))
		done := make(chan struct{})
		go func() { defer close(done); _, _ = b.Write([]byte(input)); _ = b.Close() }()
		_, e := HTTPServer(a).Read(make([]byte, 1))
		if e == nil {
			t.Fatal("invalid header accepted")
		}
		_ = a.Close()
		<-done
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e := HTTPServer(a).Read(make([]byte, 1)); e == nil {
		t.Fatal("header deadline ignored")
	}
}
