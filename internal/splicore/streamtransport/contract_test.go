package streamtransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestStreamCloseInterruptsWrite(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
		t.Run(kind, func(t *testing.T) {
			a, b, l := pair(t, kind, false)
			defer b.Close()
			defer l.Close()
			done := make(chan error, 1)
			go func() { _, e := a.Write(bytes.Repeat([]byte{1}, 32<<20)); done <- e }()
			a.Close()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("blocked write succeeded")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Close did not wake write")
			}
		})
	}
}
func TestWebSocketContinuationAndSiblingIsolation(t *testing.T) {
	a, b, l := pair(t, "ws", false)
	defer l.Close()
	defer a.Close()
	defer b.Close()
	payload := bytes.Repeat([]byte("fragment"), 12000)
	done := make(chan error, 1)
	go func() {
		got := make([]byte, len(payload))
		_, e := io.ReadFull(b, got)
		if e == nil && !bytes.Equal(got, payload) {
			e = io.ErrUnexpectedEOF
		}
		done <- e
	}()
	w, e := a.(*wsConn).ws.NextWriter(websocket.BinaryMessage)
	if e != nil {
		t.Fatal(e)
	}
	for at := 0; at < len(payload); at += 1024 {
		end := min(at+1024, len(payload))
		if _, e = w.Write(payload[at:end]); e != nil {
			t.Fatal(e)
		}
		if at == 32768 {
			a.(*wsConn).ws.WriteControl(websocket.PingMessage, []byte("owned"), time.Now().Add(time.Second))
		}
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d, _ := underlay.New().New(underlay.Scope{Purpose: underlay.ProxyUnderlay})
	c, e := Dial(ctx, d.DialContext, l.Addr().String(), cfg.Config{Kind: "ws", Path: "/shared"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	peer, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	a.Close()
	b.Close()
	go func() { _, e := c.Write([]byte("sibling")); done <- e }()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 7)
	if _, e = io.ReadFull(peer, got); e != nil || string(got) != "sibling" {
		t.Fatal("sibling affected", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func TestHTTPUpgradeClientBufferedResponseAndMalformedStatus(t *testing.T) {
	for _, response := range []string{"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nfirst", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n", "HTTP/1.1"} {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer b.Close()
			r, e := http.ReadRequest(bufio.NewReader(b))
			if e != nil {
				return
			}
			r.Body.Close()
			io.WriteString(b, response)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, e := Dial(ctx, func(context.Context, string, string) (net.Conn, error) { return a, nil }, "owned.test:80", cfg.Config{Kind: "httpupgrade"}, nil)
		if bytes.HasSuffix([]byte(response), []byte("first")) {
			if e != nil {
				t.Fatal(e)
			}
			got := make([]byte, 5)
			if _, e = io.ReadFull(c, got); e != nil || string(got) != "first" {
				t.Fatal("client buffered bytes lost", e)
			}
			c.Close()
		} else if e == nil {
			c.Close()
			t.Fatal("malformed accepted")
		}
		cancel()
		a.Close()
		<-done
	}
}
func TestAdmissionCancellation(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			a, b := net.Pipe()
			defer b.Close()
			done := make(chan error, 1)
			go func() {
				c, e := Dial(ctx, func(context.Context, string, string) (net.Conn, error) { return a, nil }, "owned.test:80", cfg.Config{Kind: kind}, nil)
				if c != nil {
					c.Close()
				}
				done <- e
			}()
			cancel()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("cancelled admission succeeded")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancelled admission stuck")
			}
		})
	}
}
func TestGRPCStickyEOF(t *testing.T) {
	a, b, l := pair(t, "grpc", false)
	defer a.Close()
	defer l.Close()
	b.Close()
	a.SetReadDeadline(time.Now().Add(time.Second))
	for range 2 {
		if _, e := a.Read(make([]byte, 1)); e == nil || os.IsTimeout(e) {
			t.Fatal("EOF not retained", e)
		}
	}
}
func TestExplicitConfigSafety(t *testing.T) {
	if got := tlsConfig(&tls.Config{NextProtos: []string{"frozen-raw"}}, "tcp"); len(got.NextProtos) != 1 || got.NextProtos[0] != "frozen-raw" {
		t.Fatal("raw TLS ALPN changed")
	}
	for _, raw := range []string{`{"kind":"ws","kind":"grpc"}`, `{"Kind":"ws"}`, `{"kind":null}`, `{"kind":"ws","path":null}`, `{"kind":"grpc","service_name":"a/b"}`, `{"kind":"ws","headers":{"Authorization":"credential"}}`} {
		var c cfg.Config
		if json.Unmarshal([]byte(raw), &c) == nil {
			t.Fatal("unsafe JSON accepted")
		}
	}
	for _, raw := range []string{`{"stream_transport":null}`, `{"Stream_Transport":{"kind":"ws"}}`} {
		if cfg.ValidateMember([]byte(raw)) == nil {
			t.Fatal("explicit selection downgraded")
		}
	}
	if (cfg.Config{Kind: "grpc"}).ValidateALPN([]string{"http/1.1"}) == nil {
		t.Fatal("incompatible ALPN")
	}
	if (cfg.Config{Kind: "ws", Headers: map[string]string{"X-Client": "value"}}).ValidateServer() == nil {
		t.Fatal("client-only headers ignored")
	}
}

func TestHTTPUpgradeHalfClose(t *testing.T) {
	a, b, l := pair(t, "httpupgrade", false)
	defer a.Close()
	defer b.Close()
	defer l.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	b.SetDeadline(time.Now().Add(time.Second))
	if e := a.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Read(make([]byte, 1)); e != io.EOF {
		t.Fatal("half-close EOF", e)
	}
	done := make(chan error, 1)
	go func() { _, e := b.Write([]byte("reply")); done <- e }()
	got := make([]byte, 5)
	if _, e := io.ReadFull(a, got); e != nil || string(got) != "reply" {
		t.Fatal("half-close lost reverse traffic", e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestGRPCExactAuthorityAndService(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	l, e := WrapListener(raw, cfg.Config{Kind: "grpc", ServiceName: "Owned", Host: "authority.synthetic.test"}, nil)
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
	defer l.Close()
	d, _ := underlay.New().New(underlay.Scope{Purpose: underlay.ProxyUnderlay})
	for _, c := range []cfg.Config{{Kind: "grpc", ServiceName: "Wrong", Host: "authority.synthetic.test"}, {Kind: "grpc", ServiceName: "Owned", Host: "wrong.synthetic.test"}, {Kind: "grpc", ServiceName: "Owned", Host: "authority.synthetic.test"}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		a, e := Dial(ctx, d.DialContext, l.Addr().String(), c, nil)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		a.SetDeadline(time.Now().Add(time.Second))
		if c.ServiceName == "Owned" && c.Host == "authority.synthetic.test" {
			go func() {
				b, e := l.Accept()
				if e != nil {
					return
				}
				defer b.Close()
				b.Write([]byte("reply"))
			}()
			got := make([]byte, 5)
			if _, e = io.ReadFull(a, got); e != nil || string(got) != "reply" {
				t.Fatal("exact endpoint", e)
			}
		} else {
			if _, e = a.Read(make([]byte, 1)); e == nil || os.IsTimeout(e) {
				t.Fatal("invalid endpoint not rejected", e)
			}
		}
		a.Close()
	}
}

type resourceSample struct{ Goroutines, FDs, Listeners, Streams, Workers int }

func sampleResources(l *listener) resourceSample {
	r := resourceSample{Goroutines: runtime.NumGoroutine(), FDs: -1}
	if f, e := os.ReadDir("/proc/self/fd"); e == nil {
		r.FDs = len(f)
	}
	if l != nil {
		l.mu.Lock()
		r.Streams = len(l.connections)
		if l.ctx.Err() == nil {
			r.Listeners = 1
		}
		r.Workers = len(l.streams) * 2
		l.mu.Unlock()
	}
	return r
}
func TestTransportResourceX25(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
		t.Run(kind, func(t *testing.T) {
			// Warm lazy global runtime/library initialization before measuring ownership.
			a, b, l := pair(t, kind, false)
			a.Close()
			b.Close()
			l.Close()
			runtime.GC()
			start := sampleResources(nil)
			peak := start
			for cycle := range 25 {
				a, b, l := pair(t, kind, false)
				ll := l.(*listener)
				d := make(chan error, 1)
				go func() { _, e := a.Write([]byte("owned-lifetime")); d <- e }()
				got := make([]byte, 14)
				if _, e := io.ReadFull(b, got); e != nil {
					t.Fatal(e)
				}
				if e := <-d; e != nil {
					t.Fatal(e)
				}
				r := sampleResources(ll)
				peak.Goroutines = max(peak.Goroutines, r.Goroutines)
				peak.FDs = max(peak.FDs, r.FDs)
				peak.Listeners = max(peak.Listeners, r.Listeners)
				peak.Streams = max(peak.Streams, r.Streams)
				peak.Workers = max(peak.Workers, r.Workers)
				a.Close()
				b.Close()
				l.Close()
				r = sampleResources(ll)
				if r.Listeners != 0 || r.Streams != 0 || r.Workers != 0 {
					t.Fatalf("cycle %d retained owned resources %+v", cycle, r)
				}
			}
			runtime.GC()
			end := sampleResources(nil)
			if end.FDs != start.FDs || end.Goroutines > start.Goroutines {
				t.Fatalf("resource growth start=%+v end=%+v", start, end)
			}
			t.Logf("transport=%s cycles=25 start=%+v peak=%+v end=%+v", kind, start, peak, end)
		})
	}
}
