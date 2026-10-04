package clientruntime

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

func TestHTTPMixedLifecycleBufferedConnectPlainHTTPAndSOCKS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	workers := make(chan struct{})
	go func() {
		defer close(workers)
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); io.Copy(c, c) }()
		}
	}()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" || r.Header.Get("X-Hop-Second") != "" {
			t.Error("proxy header forwarded")
		}
		conn, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: X-Return, close\r\nConnection: X-Return-Second\r\nX-Return: private\r\nX-Return-Second: private\r\n\r\nplain-http-integrity")
	}))
	defer target.Close()
	factories, _ := registry.NewOutbounds()
	for cycle := 0; cycle < 10; cycle++ {
		m := New()
		state := client.Empty()
		lid, _ := identity.NewID()
		reserved, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		port := uint16(reserved.Addr().(*net.TCPAddr).Port)
		reserved.Close()
		state.LocalInbounds = []client.LocalInbound{{ID: lid, Name: "fixture", Kind: "mixed", Listen: access.Endpoint{Host: "127.0.0.1", Port: port}}}
		p, e := m.Prepare(ctx, state, nil, factories)
		if e != nil {
			t.Fatal(e)
		}
		p.Activate()
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		c, e := net.DialTimeout("tcp", addr, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		payload := bytes.Repeat([]byte("buffered-connect"), 1024)
		request := []byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr()))
		c.Write(append(request, payload...))
		reader := bufio.NewReader(c)
		resp, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if e != nil || resp.StatusCode != 200 {
			t.Fatal("connect", e)
		}
		returned := make([]byte, len(payload))
		if _, e = io.ReadFull(reader, returned); e != nil || !bytes.Equal(payload, returned) {
			t.Fatal("buffered CONNECT", e)
		}
		c.Close()
		c, e = net.DialTimeout("tcp", addr, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "GET %s/ HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: synthetic\r\nConnection: X-Hop\r\nConnection: X-Hop-Second\r\nX-Hop: private\r\nX-Hop-Second: private\r\n\r\n", target.URL, target.Listener.Addr())
		resp, e = http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
		if e != nil {
			t.Fatal(e)
		}
		data, e := io.ReadAll(resp.Body)
		resp.Body.Close()
		c.Close()
		if e != nil || string(data) != "plain-http-integrity" || resp.Header.Get("X-Return") != "" || resp.Header.Get("X-Return-Second") != "" {
			t.Fatalf("plain HTTP: %v, body %q, headers %v", e, string(data), resp.Header)
		}
		c, e = net.DialTimeout("tcp", addr, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e = socks.ClientHandshake5(c, socks5.CommandConnect, M.SocksaddrFromNet(echo.Addr()), "", ""); e != nil {
			t.Fatal(e)
		}
		c.Write([]byte("socks"))
		data = make([]byte, 5)
		if _, e = io.ReadFull(c, data); e != nil || string(data) != "socks" {
			t.Fatal("mixed SOCKS", e)
		}
		c.Close()
		if e = m.WaitIdle(ctx); e != nil {
			t.Fatal(e)
		}
		if e = m.Close(ctx); e != nil {
			t.Fatal(e)
		}
		reserved, e = net.Listen("tcp", addr)
		if e != nil {
			t.Fatal("socket leaked", e)
		}
		reserved.Close()
	}
	echo.Close()
	<-workers
}
