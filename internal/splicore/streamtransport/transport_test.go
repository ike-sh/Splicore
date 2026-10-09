package streamtransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func pair(t *testing.T, kind string, secure bool) (net.Conn, net.Conn, net.Listener) {
	t.Helper()
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Close() })
	c := cfg.Config{Kind: kind, Path: "/shared"}
	if kind == "grpc" {
		c.Path = ""
		c.ServiceName = "SharedTest"
	}
	var server, client *tls.Config
	if secure {
		m := testkit.TLSForName(t, "transport.synthetic.test")
		cert, e := os.ReadFile(m.CertificateFile)
		if e != nil {
			t.Fatal(e)
		}
		key, e := os.ReadFile(m.PrivateKeyFile)
		if e != nil {
			t.Fatal(e)
		}
		p, e := tls.X509KeyPair(cert, key)
		if e != nil {
			t.Fatal(e)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(m.CACertificate))
		server = &tls.Config{Certificates: []tls.Certificate{p}, MinVersion: tls.VersionTLS12}
		client = &tls.Config{ServerName: m.ServerName, RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	l, e := WrapListener(raw, c, server)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		v, e := l.Accept()
		if e != nil {
			acceptErr <- e
			return
		}
		accepted <- v
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, _ := underlay.New().New(underlay.Scope{Purpose: underlay.ProxyUnderlay})
	a, e := Dial(ctx, d.DialContext, l.Addr().String(), c, client)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Close() })
	select {
	case b := <-accepted:
		t.Cleanup(func() { b.Close() })
		return a, b, l
	case e := <-acceptErr:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return nil, nil, nil
}
func TestStreamLifecycle(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
		for _, secure := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "-plain", true: "-tls"}[secure], func(t *testing.T) {
				a, b, l := pair(t, kind, secure)
				a.SetDeadline(time.Now().Add(5 * time.Second))
				b.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte("bounded-stream"), 100000)
				done := make(chan error, 1)
				go func() { _, e := io.Copy(b, b); done <- e }()
				written := make(chan error, 1)
				go func() { _, e := a.Write(payload); written <- e }()
				got := make([]byte, len(payload))
				if _, e := io.ReadFull(a, got); e != nil {
					t.Fatal(e)
				}
				if e := <-written; e != nil || !bytes.Equal(got, payload) {
					t.Fatal("payload mismatch", e)
				}
				a.SetDeadline(time.Time{})
				b.SetDeadline(time.Time{})
				a.Close()
				b.Close()
				<-done
				l.Close()
				if _, e := l.Accept(); e == nil {
					t.Fatal("Accept after Close")
				}
			})
		}
	}
}
func TestLiveDeadlinesAndClose(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
		t.Run(kind, func(t *testing.T) {
			a, b, l := pair(t, kind, false)
			result := make(chan error, 1)
			go func() { _, e := a.Read(make([]byte, 1)); result <- e }()
			a.SetReadDeadline(time.Now().Add(-time.Second))
			select {
			case e := <-result:
				if e == nil {
					t.Fatal("deadline not applied")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocked read ignored dynamic deadline")
			}
			a.Close()
			b.Close()
			l.Close()
			a, b, l = pair(t, kind, false)
			started := make(chan struct{})
			go func() { close(started); _, e := a.Write(bytes.Repeat([]byte{8}, 16<<20)); result <- e }()
			<-started
			a.SetWriteDeadline(time.Now().Add(-time.Second))
			select {
			case e := <-result:
				if e == nil {
					t.Fatal("blocked write ignored deadline")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("write stuck")
			}
			a.Close()
			b.Close()
			l.Close()
			a, b, l = pair(t, kind, false)
			go func() { _, e := b.Read(make([]byte, 1)); result <- e }()
			l.Close()
			select {
			case e := <-result:
				if e == nil {
					t.Fatal("parent shutdown")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("parent failed to wake stream")
			}
			a.Close()
			b.Close()
		})
	}
}
func TestHTTPUpgradeBufferedBytesAndRejection(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	l, e := WrapListener(raw, cfg.Config{Kind: "httpupgrade", Path: "/exact", Host: "transport.test"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	client, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	request := "GET /exact HTTP/1.1\r\nHost: transport.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nfirst-payload"
	for _, s := range []string{request[:17], request[17:]} {
		if _, e = io.WriteString(client, s); e != nil {
			t.Fatal(e)
		}
	}
	server, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	server.SetDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len("first-payload"))
	if _, e = io.ReadFull(server, got); e != nil || string(got) != "first-payload" {
		t.Fatal("buffer lost", e)
	}
	br := bufio.NewReader(client)
	for {
		line, e := br.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if line == "\r\n" {
			break
		}
	}
	_, e = io.WriteString(server, "reply")
	if e != nil {
		t.Fatal(e)
	}
	got = make([]byte, 5)
	if _, e = io.ReadFull(br, got); e != nil || string(got) != "reply" {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d, _ := underlay.New().New(underlay.Scope{Purpose: underlay.ProxyUnderlay})
	bad := cfg.Config{Kind: "httpupgrade", Path: "/wrong", Host: "transport.test"}
	if c, e := Dial(ctx, d.DialContext, l.Addr().String(), bad, nil); e == nil {
		c.Close()
		t.Fatal("unknown path accepted")
	}
}
func TestWebSocketControlAndBinary(t *testing.T) {
	a, b, l := pair(t, "ws", false)
	defer l.Close()
	defer a.Close()
	defer b.Close()
	client := a.(*wsConn)
	server := b.(*wsConn)
	done := make(chan error, 1)
	go func() {
		got := make([]byte, 6)
		_, e := io.ReadFull(server, got)
		if e == nil && string(got) != "abcdef" {
			e = errors.New("fragmentation mismatch")
		}
		done <- e
	}()
	// A small writer buffer forces RFC continuation frames without inspecting
	// dependency internals. Ping interleaves with the binary message.
	client.ws.SetPongHandler(func(string) error { return nil })
	client.ws.SetWriteDeadline(time.Now().Add(2 * time.Second))
	w, e := client.ws.NextWriter(websocket.BinaryMessage)
	if e != nil {
		t.Fatal(e)
	}
	w.Write([]byte("abc"))
	if e = client.ws.WriteControl(websocket.PingMessage, []byte("probe"), time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	w.Write([]byte("def"))
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	read := make(chan error, 1)
	go func() { _, e := server.Read(make([]byte, 1)); read <- e }()
	if e = client.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1000, ""), time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if e = <-read; e != io.EOF {
		t.Fatal("normal close", e)
	}
}
func TestTransportLifecycleX25(t *testing.T) {
	before := runtime.NumGoroutine()
	for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
		t.Run(kind, func(t *testing.T) {
			for i := 0; i < 25; i++ {
				a, b, l := pair(t, kind, false)
				a.Close()
				b.Close()
				l.Close()
				if ll, ok := l.(*listener); ok {
					ll.mu.Lock()
					n := len(ll.connections)
					ll.mu.Unlock()
					if n != 0 {
						t.Fatalf("remaining owned connections %d", n)
					}
				}
			}
		})
	}
	t.Logf("goroutines start=%d end=%d (no owned listeners/connections remain)", before, runtime.NumGoroutine())
}
func TestConfigSecurity(t *testing.T) {
	for _, c := range []cfg.Config{{Kind: "xhttp"}, {Kind: "ws", Path: "/?ed=128"}, {Kind: "grpc", ServiceName: "/extended/path"}, {Kind: "ws", Headers: map[string]string{"Upgrade": "bad"}}, {Kind: "ws", Headers: map[string]string{"X-Test": "x\r\nInjected: 1"}}, {Kind: "tcp", Path: "/drop"}, {Kind: "grpc", Path: "/bad"}} {
		if c.Validate() == nil {
			t.Fatalf("unsafe accepted: %s", c.Type())
		}
	}
	if (cfg.Config{Kind: "ws"}).ValidatePair("vless", "reality") == nil {
		t.Fatal("REALITY generalized")
	}
}
func FuzzTransportConfig(f *testing.F) {
	f.Add([]byte(`{"kind":"ws","path":"/test"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 16384 {
			return
		}
		var c cfg.Config
		if json.Unmarshal(b, &c) == nil {
			_ = c.Validate()
		}
	})
}
func FuzzGRPCMessage(f *testing.F) {
	f.Add([]byte{10, 3, 'a', 'b', 'c'})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxMessage+16 {
			return
		}
		var m hunk
		if (hunkCodec{}).Unmarshal(b, &m) == nil {
			encoded, e := (hunkCodec{}).Marshal(&m)
			if e != nil {
				t.Fatal(e)
			}
			var second hunk
			if (hunkCodec{}).Unmarshal(encoded, &second) != nil || !bytes.Equal(m.data, second.data) {
				t.Fatal("protobuf roundtrip")
			}
		}
	})
}
