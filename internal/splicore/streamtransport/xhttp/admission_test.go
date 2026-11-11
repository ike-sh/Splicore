package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	vless "github.com/ike-sh/Splicore/protocol/vless/wire"
)

func admissionPipe(chunk int) (*logicalConn, net.Conn) {
	a, b := net.Pipe()
	return &logicalConn{Conn: a, close: func() { a.Close() }, admissionChunk: chunk}, b
}

func TestXHTTPAdmissionFragmentMatrix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		delay   time.Duration
		payload int
	}{
		{"immediate", 1, 0, 41}, {"below-old-boundary", 1, 4999 * time.Millisecond, 41},
		{"above-old-boundary", 1, 6 * time.Second, 41}, {"many-one-byte", 1, 4 * time.Second, 100},
		{"many-small", 3, 2 * time.Second, 300}, {"single-post", 65536, 0, 41},
		{"large-post", 65536, 0, 65536}, {"maximum-interval", 1, 20 * time.Second, 41},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := admissionListener()
				l.config.XHTTP.Buffered = 1024
				defer l.Close()
				cancel, done := downRequest(t, l, "fragments")
				defer cancel()
				l.mu.Lock()
				s := l.sessions["fragments"]
				l.mu.Unlock()
				original := bytes.Repeat([]byte("x"), tc.payload)
				go func() {
					for off, seq := 0, uint64(0); off < len(original); seq++ {
						if off > 0 {
							time.Sleep(tc.delay)
						}
						end := min(len(original), off+tc.size)
						if err := s.enqueue(seq, original[off:end]); err != nil {
							return
						}
						off = end
					}
				}()
				logical, err := l.Accept()
				if err != nil {
					t.Fatal(err)
				}
				c, finish := logical.(*logicalConn).BeginAdmission(5 * time.Second)
				defer c.Close()
				got := make([]byte, len(original))
				if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, original) {
					t.Fatal("loss/duplication/reordering", err)
				}
				if err = finish(); err != nil {
					t.Fatal(err)
				}
				c.SetReadDeadline(time.Now().Add(time.Second))
				if _, err = c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal("ordinary absolute deadline", err)
				}
				c.Close()
				<-done
			})
		})
	}
}

func TestXHTTPAdmissionActualVLESSCodec(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var encoded bytes.Buffer
		want := vless.Request{Command: vless.TCP, Destination: access.Endpoint{Host: "example.test", Port: 443}}
		if err := vless.WriteRequest(&encoded, want); err != nil {
			t.Fatal(err)
		}
		logical, peer := admissionPipe(1)
		defer peer.Close()
		c, finish := logical.BeginAdmission(5 * time.Second)
		defer c.Close()
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			for i, v := range encoded.Bytes() {
				if i > 0 {
					time.Sleep(6 * time.Second)
				}
				if _, err := peer.Write([]byte{v}); err != nil {
					return
				}
			}
		}()
		got, err := vless.ReadRequest(c)
		if err != nil || got.Destination != want.Destination {
			t.Fatal("exact 1-byte/6s codec counterexample", got, err)
		}
		if err = finish(); err != nil {
			t.Fatal(err)
		}
		<-finished
	})
}

func TestXHTTPAdmissionOutboundFragmentWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logical, peer := admissionPipe(1)
		defer peer.Close()
		c, finish := logical.BeginAdmission(5 * time.Second)
		defer c.Close()
		want := []byte("complete generic admission written one byte at a time")
		got := make([]byte, len(want))
		done := make(chan error, 1)
		go func() {
			for i := range got {
				if i > 0 {
					time.Sleep(6 * time.Second)
				}
				if _, err := io.ReadFull(peer, got[i:i+1]); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
		if n, err := c.Write(want); err != nil || n != len(want) {
			t.Fatal(n, err)
		}
		if err := <-done; err != nil || !bytes.Equal(got, want) {
			t.Fatal("outbound bytes", err)
		}
		if err := finish(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestXHTTPAdmissionBoundsAndCancellation(t *testing.T) {
	for _, name := range []string{"missing-remainder", "peer-close", "context-cancel", "processing-budget", "step-limit", "byte-limit", "wall-limit"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logical, peer := admissionPipe(1)
				defer peer.Close()
				c, finish := logical.BeginAdmission(5 * time.Second)
				defer c.Close()
				switch name {
				case "missing-remainder":
					go peer.Write([]byte{1})
					b := make([]byte, 2)
					_, err := io.ReadFull(c, b)
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatal(err)
					}
				case "peer-close":
					peer.Close()
					if _, err := c.Read(make([]byte, 1)); err == nil {
						t.Fatal("close ignored")
					}
				case "context-cancel":
					ctx, cancel := context.WithCancel(context.Background())
					stop := context.AfterFunc(ctx, func() { c.Close() })
					defer stop()
					go cancel()
					if _, err := c.Read(make([]byte, 1)); err == nil {
						t.Fatal("cancellation ignored")
					}
				case "processing-budget":
					time.Sleep(5*time.Second + time.Nanosecond)
					if err := finish(); !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatal(err)
					}
				case "step-limit":
					go func() {
						for i := 0; i < admissionSteps+1; i++ {
							if _, err := peer.Write([]byte{1}); err != nil {
								return
							}
						}
					}()
					if _, err := io.ReadFull(c, make([]byte, admissionSteps+1)); !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatal(err)
					}
				case "byte-limit":
					go peer.Write(make([]byte, admissionBytes+1))
					if _, err := c.Read(make([]byte, admissionBytes+1)); !errors.Is(err, io.ErrShortBuffer) {
						t.Fatal(err)
					}
				case "wall-limit":
					a := c.(*admissionConn)
					a.mu.Lock()
					a.wall.Stop()
					a.until = time.Now().Add(time.Second)
					a.wall.Reset(time.Second)
					a.mu.Unlock()
					if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatal(err)
					}
				}
			})
		})
	}
}

func TestXHTTPAdmissionConcurrentSessions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(v byte) {
				defer wg.Done()
				logical, peer := admissionPipe(1)
				defer peer.Close()
				c, finish := logical.BeginAdmission(5 * time.Second)
				defer c.Close()
				go func() { peer.Write([]byte{v}); time.Sleep(6 * time.Second); peer.Write([]byte{v}) }()
				b := make([]byte, 2)
				if _, err := io.ReadFull(c, b); err != nil || !bytes.Equal(b, []byte{v, v}) {
					t.Error(b, err)
				}
				if err := finish(); err != nil {
					t.Error(err)
				}
			}(byte(i))
		}
		wg.Wait()
	})
}

func TestXHTTPQueryInHeaderURLGrammar(t *testing.T) {
	for _, path := range []string{"/normal/path", "/path,with,comma", "/,leading-comma", "/trailing,", "/a,b/c,d", "/a%2Cb", "/a,b/?tenant=a,b"} {
		for _, placement := range []string{"queryInHeader", "header", "query", "cookie"} {
			t.Run(path+"/"+placement, func(t *testing.T) {
				c := cfg.Config{Kind: "xhttp", Path: path, Headers: map[string]string{"X-Application": "one,two"}, XHTTP: &cfg.XHTTP{Mode: "packet-up", PaddingObfs: true, PaddingPlacement: placement, Padding: cfg.Range{Min: 1, Max: 1}}}
				if err := c.Validate(); err != nil {
					t.Fatal(err)
				}
				semantic, q := c.XHTTPPath()
				target := "http://example.test" + semantic
				if q != "" {
					target += "?" + q
				}
				r := httptest.NewRequest("POST", target, nil)
				if err := decorate(r, c, "id", "0", false, rand.Reader); err != nil {
					t.Fatal(err)
				}
				wire := r.URL.String()
				r.URL = nil
				parsed := httptest.NewRequest("POST", wire, nil)
				parsed.Header = r.Header
				if !strings.HasPrefix(parsed.URL.Path, semantic) {
					t.Fatal("semantic path changed", parsed.URL)
				}
				if sid, seq, err := parseEnvelope(parsed, c); err != nil || sid != "id" || seq != "0" {
					t.Fatal(sid, seq, err)
				}
			})
		}
	}
	c := cfg.Config{Kind: "xhttp", Path: "/a,b", XHTTP: &cfg.XHTTP{PaddingObfs: true, PaddingPlacement: "queryInHeader", Padding: cfg.Range{Min: 1, Max: 1}}}
	for _, carrier := range []string{"http://example.test/a,b/?x_padding=X&x_padding=X", "http://example.test/%xx?x_padding=X", "http://example.test/a,b/?x_padding=X,X", "http://example.test/a,b/?other=X", "http://example.test/a,b/?x_padding=X;other=X"} {
		r := httptest.NewRequest("POST", "http://example.test/a,b/", nil)
		decorate(r, c, "id", "0", false, rand.Reader)
		r.Header.Set("X-Padding", carrier)
		if _, _, err := parseEnvelope(r, c); err == nil {
			t.Fatal("invalid URL padding accepted", carrier)
		}
	}
	for _, form := range []string{"case", "multi"} {
		r := httptest.NewRequest("POST", "http://example.test/a,b/", nil)
		decorate(r, c, "id", "0", false, rand.Reader)
		if form == "case" {
			r.Header["x-padding"] = []string{r.Header.Get("X-Padding")}
		} else {
			r.Header.Add("X-Padding", r.Header.Get("X-Padding"))
		}
		if _, _, err := parseEnvelope(r, c); err == nil {
			t.Fatal("URL carrier duplicate bypass")
		}
	}
}

func TestXHTTPQueryInHeaderInvalidConfiguration(t *testing.T) {
	for _, x := range []cfg.XHTTP{
		{PaddingObfs: true, PaddingPlacement: "queryInHeader,X-Padding"},
		{PaddingObfs: true, PaddingPlacement: "queryInHeader", PaddingHeader: "X-Padding,Other"},
		{PaddingObfs: true, PaddingPlacement: "queryInHeader", PaddingKey: "x_padding,other"},
		{PaddingObfs: true, PaddingPlacement: "queryInHeader", SessionPlacement: "header", SessionKey: "x-padding"},
	} {
		if err := (cfg.Config{Kind: "xhttp", Path: "/a,b", XHTTP: &x}).Validate(); err == nil {
			t.Fatal("invalid structured config accepted", x)
		}
	}
}
