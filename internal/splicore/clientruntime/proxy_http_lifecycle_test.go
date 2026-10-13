package clientruntime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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
	var originWorkers sync.WaitGroup
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originWorkers.Add(1)
		defer originWorkers.Done()
		w.Header().Set("Content-Length", "100000")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		canceled <- struct{}{}
	}))
	defer origin.Close()
	bodyClosures, cancellations, detections := 0, 0, 0
	var errorDelta int64
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
			cancellations++
		case <-time.After(2 * time.Second):
			t.Fatal("stalled origin response retained after Close")
		}
		resp.Body.Close()
		bodyClosures++
		c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		e = m.WaitIdle(ctx)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		if !parent {
			const operations = 256
			before := m.Status(state, nil).LocalStats[0].Stats.Errors
			peers := make([]net.Conn, 0, operations)
			defer func() {
				for _, peer := range peers {
					peer.Close()
				}
			}()
			for range operations {
				c, e := net.DialTimeout("tcp", address, time.Second)
				if e != nil {
					t.Fatal(e)
				}
				peers = append(peers, c)
				c.SetDeadline(time.Now().Add(2 * time.Second))
				if n, e := io.WriteString(c, "CO"); e != nil || n != 2 {
					t.Fatal("incomplete detection submission", n, e)
				}
				// Send the same terminal EOF while retaining the read side for
				// the server's close acknowledgement. Dial/Write alone do not
				// prove that Accept has registered the connection.
				if e := c.(*net.TCPConn).CloseWrite(); e != nil {
					t.Fatal(e)
				}
			}
			// Keep all submissions ahead of this barrier, so server-side churn
			// still overlaps. Each close follows Detect's error accounting;
			// WaitIdle can then observe cleanup without missing queued accepts.
			type outcome struct {
				bytes int
				err   error
			}
			results := make(chan outcome, operations)
			var readers sync.WaitGroup
			for _, peer := range peers {
				readers.Go(func() {
					b, err := io.ReadAll(peer)
					peer.Close()
					results <- outcome{len(b), err}
				})
			}
			for range operations {
				result := <-results
				if result.err != nil || result.bytes != 0 {
					t.Error("incomplete detection did not terminate with empty EOF", result.bytes, result.err)
				} else {
					detections++
				}
			}
			readers.Wait()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			e = m.WaitIdle(ctx)
			cancel()
			if e != nil {
				t.Fatal(e)
			}
			v := m.Status(state, nil).LocalStats[0].Stats
			errorDelta = v.Errors - before
			if detections != operations || errorDelta != operations {
				t.Fatalf("incomplete detection accounting: submitted=%d EOF=%d error_delta=%d stats=%+v", operations, detections, errorDelta, v)
			}
			t.Logf("256 incomplete Mixed detections joined; errors=%d error_delta=%d; client body cancellation PASS", v.Errors, errorDelta)
		}
	}
	originWorkers.Wait()
	m.mu.Lock()
	pendingSessions, pendingListeners := len(m.sessions), len(m.listeners)
	m.mu.Unlock()
	if bodyClosures != 2 || cancellations != 2 || pendingSessions != 0 || pendingListeners != 0 {
		t.Fatal("HTTP cancellation cleanup", bodyClosures, cancellations, pendingSessions, pendingListeners)
	}
	t.Logf("phase20_metrics started=256 completed=%d detection_eof=%d error_delta=%d body_closures=%d cancellations=%d origin_handlers_remaining=0 owned_readers_remaining=0 manager_sessions_remaining=%d manager_listeners_remaining=%d", detections, detections, errorDelta, bodyClosures, cancellations, pendingSessions, pendingListeners)
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
