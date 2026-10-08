package clientruntime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPhase20HTTPBodyCancellationAndMixedDetectionChurn(t *testing.T) {
	m, state, r, _ := udpFixture(t)
	state.LocalInbounds[0].Kind = "mixed"
	reserved, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	state.LocalInbounds[0].Listen.Port = uint16(reserved.Addr().(*net.TCPAddr).Port)
	reserved.Close()
	p, e := m.PrepareWithRestart(context.Background(), state, nil, r, true)
	if e != nil {
		t.Fatal(e)
	}
	p.Activate()
	address := fmt.Sprintf("127.0.0.1:%d", state.LocalInbounds[0].Listen.Port)
	canceled := make(chan struct{}, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		canceled <- struct{}{}
	}))
	defer origin.Close()
	for _, parent := range []bool{false, true} {
		c, e := net.DialTimeout("tcp", address, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprintf(c, "GET %s/ HTTP/1.1\r\nHost: %s\r\n\r\n", origin.URL, origin.Listener.Addr())
		resp, e := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
		if e != nil {
			c.Close()
			t.Fatal(e)
		}
		if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
		if parent {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			e = m.Close(ctx)
			cancel()
			if e != nil {
				t.Fatal(e)
			}
		} else {
			c.Close()
		}
		select {
		case <-canceled:
		case <-time.After(2 * time.Second):
			t.Fatal("stalled origin response retained after Close")
		}
		resp.Body.Close()
		c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		e = m.WaitIdle(ctx)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		if !parent {
			for range 256 {
				c, e := net.DialTimeout("tcp", address, time.Second)
				if e != nil {
					t.Fatal(e)
				}
				io.WriteString(c, "CO")
				c.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			e = m.WaitIdle(ctx)
			cancel()
			if e != nil {
				t.Fatal(e)
			}
			v := m.Status(state, nil).LocalStats[0].Stats
			if v.Errors < 256 {
				t.Fatalf("missing detection error stats %+v", v)
			}
			t.Logf("256 incomplete Mixed detections joined; errors=%d; client body cancellation PASS", v.Errors)
		}
	}
	t.Log("parent Close canceled stalled HTTP response and joined detection/body readers")
}

func TestPhase20HTTPConnectHalfClose(t *testing.T) {
	m, state, r, _ := udpFixture(t)
	state.LocalInbounds[0].Kind = "http"
	reserved, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	state.LocalInbounds[0].Listen.Port = uint16(reserved.Addr().(*net.TCPAddr).Port)
	reserved.Close()
	p, e := m.PrepareWithRestart(context.Background(), state, nil, r, true)
	if e != nil {
		t.Fatal(e)
	}
	p.Activate()
	target, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	done := make(chan error, 1)
	go func() {
		c, e := target.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		b, e := io.ReadAll(c)
		if e == nil {
			_, e = c.Write(b)
		}
		done <- e
	}()
	c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", state.LocalInbounds[0].Listen.Port), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Addr(), target.Addr())
	reader := bufio.NewReader(c)
	resp, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if e != nil || resp.StatusCode != 200 {
		t.Fatal(e)
	}
	io.WriteString(c, "half-close-payload")
	if e = c.(*net.TCPConn).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(reader)
	if e != nil || string(b) != "half-close-payload" {
		t.Fatal("half-close response", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	t.Log("CONNECT client CloseWrite retains downstream response payload")
}
