//go:build with_quic

package xhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type h3BodyProbeConn struct {
	conn     *quic.Conn
	server   *http3.Server
	requests atomic.Int32
}

func TestXHTTPH3StreamBodyUnsentGOAWAY(t *testing.T) {
	for _, plainLibrary := range []bool{false, true} {
		t.Run(fmt.Sprintf("plain_library=%t", plainLibrary), func(t *testing.T) {
			unusedClient, backend, _ := h3Fixture(t, cfg.Config{Kind: "xhttp"})
			unusedClient.Close()
			st, ct := tlsPair(t)
			st.NextProtos, ct.NextProtos = []string{"h3"}, []string{"h3"}
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			transport := &quic.Transport{Conn: packet}
			qc := h3QUICConfig(true, 0)
			// The first live stream occupies the only request-stream credit.
			// The second request cannot open a stream or send any HTTP bytes.
			qc.MaxIncomingStreams = 1
			listener, err := transport.Listen(st, qc)
			if err != nil {
				transport.Close()
				packet.Close()
				t.Fatal(err)
			}
			accepted := make(chan *h3BodyProbeConn, 8)
			var workers sync.WaitGroup
			workers.Go(func() {
				for {
					q, err := listener.Accept(context.Background())
					if err != nil {
						return
					}
					entry := &h3BodyProbeConn{conn: q}
					entry.server = &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						entry.requests.Add(1)
						backend.ServeHTTP(w, r)
					})}
					accepted <- entry
					workers.Go(func() { _ = entry.server.ServeQUICConn(q) })
				}
			})
			t.Cleanup(func() {
				listener.Close()
				transport.Close()
				packet.Close()
				backend.Close()
				workers.Wait()
			})
			var dials atomic.Int32
			client, err := NewClient(func(context.Context, string, string) (net.Conn, error) {
				return nil, fmt.Errorf("unexpected TCP fallback")
			}, listener.Addr().String(), cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{
				Mode: "stream-one", XMUX: &cfg.XMUX{MaxConnections: cfg.Range{Min: 1, Max: 1}},
			}}, Security{TLS: ct, PacketSocket: func(context.Context) (net.PacketConn, net.Addr, error) {
				dials.Add(1)
				p, e := net.ListenPacket("udp4", "127.0.0.1:0")
				return p, listener.Addr(), e
			}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			if plainLibrary {
				entry, err := client.pool.lease()
				if err != nil {
					t.Fatal(err)
				}
				owned := entry.transport.(*h3Transport)
				// Control: use the existing embedded quic-go transport, retaining
				// the same production UDP dialer. No source overlay replacement.
				entry.transport = owned.Transport
				client.pool.release(entry)
				t.Cleanup(func() { client.Close(); owned.Close() })
			}
			selected := make(chan struct{})
			var selections atomic.Int32
			var writeErrors atomic.Int32
			client.ctx = httptrace.WithClientTrace(client.ctx, &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) {
					n := selections.Add(1)
					t.Logf("GotConn selection=%d local=%v reused=%t", n, info.Conn.LocalAddr(), info.Reused)
					if n == 2 {
						close(selected)
					}
				},
				WroteRequest: func(info httptrace.WroteRequestInfo) {
					if info.Err != nil {
						writeErrors.Add(1)
						t.Logf("WroteRequest error: %v", info.Err)
					}
				},
			})
			first, err := client.DialContext(context.Background())
			if err != nil {
				t.Fatal("first DialContext", err)
			}
			defer first.Close()
			exchange(t, first, []byte("first stream keeps connection alive"))
			var old *h3BodyProbeConn
			select {
			case old = <-accepted:
			case <-time.After(3 * time.Second):
				t.Fatal("first QUIC accept timeout")
			}
			secondResult := make(chan h3CarrierResult, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			go func() { c, e := client.DialContext(ctx); secondResult <- h3CarrierResult{conn: c, err: e} }()
			select {
			case <-selected:
			case <-time.After(3 * time.Second):
				t.Fatal("second request did not select cached connection")
			}
			if got := old.requests.Load(); got != 1 {
				t.Fatalf("old connection handled %d requests before GOAWAY, want 1", got)
			}
			shutdownContext, shutdownCancel := context.WithCancel(context.Background())
			defer shutdownCancel()
			workers.Go(func() { _ = old.server.Shutdown(shutdownContext) })
			var second h3CarrierResult
			select {
			case second = <-secondResult:
			case <-time.After(5 * time.Second):
				t.Fatal("safe retry never returned")
			}
			// The first stream remains alive: this is a graceful GOAWAY, not
			// physical connection failure, and cleanup must not break that user.
			exchange(t, first, []byte("first stream survives graceful GOAWAY"))
			t.Logf("after retry: dials=%d GotConn=%d old_handled_requests=%d write_errors=%d dial_error=%v", dials.Load(), selections.Load(), old.requests.Load(), writeErrors.Load(), second.err)
			if old.requests.Load() != 1 {
				t.Error("second request unexpectedly reached old server")
			}
			if second.err != nil {
				t.Fatalf("safe retry of unsent streaming request failed: %v", second.err)
			}
			defer second.conn.Close()
			// Both directions must work on the replacement connection.
			_ = second.conn.SetDeadline(time.Now().Add(2 * time.Second))
			payload := []byte("second stream safe retry payload")
			sent := make(chan error, 1)
			go func() { _, e := second.conn.Write(payload); sent <- e }()
			got := make([]byte, len(payload))
			_, readErr := io.ReadFull(second.conn, got)
			writeErr := <-sent
			if readErr != nil || writeErr != nil || string(got) != string(payload) {
				t.Fatalf("safe retry returned unusable stream: read=%v write=%v got=%q", readErr, writeErr, got)
			}
		})
	}
}

// Use real GOAWAY / stream credit and count the original reader, rather than
// synthesizing the retry sentinel or changing the production transport.
type h3BodyFixture struct {
	transport *h3Transport
	target    string
	accepted  chan *h3BodyProbeConn
	dials     atomic.Int32
	workers   sync.WaitGroup
	close     func()
}

func newH3BodyFixture(t *testing.T, handler func(int, http.ResponseWriter, *http.Request), gate func(context.Context, int) error) *h3BodyFixture {
	t.Helper()
	st, ct := tlsPair(t)
	st.NextProtos, ct.NextProtos = []string{"h3"}, []string{"h3"}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: packet}
	qc := h3QUICConfig(true, 0)
	qc.MaxIncomingStreams = 1
	listener, err := tr.Listen(st, qc)
	if err != nil {
		tr.Close()
		packet.Close()
		t.Fatal(err)
	}
	f := &h3BodyFixture{target: "https://" + listener.Addr().String() + "/", accepted: make(chan *h3BodyProbeConn, 8)}
	f.workers.Go(func() {
		index := 0
		for {
			q, e := listener.Accept(context.Background())
			if e != nil {
				return
			}
			index++
			generation := index
			entry := &h3BodyProbeConn{conn: q}
			entry.server = &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entry.requests.Add(1)
				handler(generation, w, r)
			})}
			f.accepted <- entry
			f.workers.Go(func() { _ = entry.server.ServeQUICConn(q) })
		}
	})
	f.transport = newH3Transport(Security{TLS: ct, PacketSocket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		n := int(f.dials.Add(1))
		if gate != nil {
			if err := gate(ctx, n); err != nil {
				return nil, nil, err
			}
		}
		p, e := net.ListenPacket("udp4", "127.0.0.1:0")
		return p, listener.Addr(), e
	}}, 0).(*h3Transport)
	f.close = sync.OnceFunc(func() {
		f.transport.Close()
		listener.Close()
		tr.Close()
		packet.Close()
		joined := make(chan struct{})
		go func() { f.workers.Wait(); close(joined) }()
		carrierReceive(t, joined)
		h3ReclaimBound(t, f.transport, 0, 0, 0)
	})
	t.Cleanup(f.close)
	return f
}

func (f *h3BodyFixture) shutdown(t *testing.T, old *h3BodyProbeConn) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.workers.Go(func() { _ = old.server.Shutdown(ctx) })
}

type h3CountedStream struct {
	io.ReadCloser
	reads, closes atomic.Int32
	closed        chan struct{}
}

func (b *h3CountedStream) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.ReadCloser.Read(p)
}

func (b *h3CountedStream) Close() error {
	if b.closes.Add(1) == 1 {
		close(b.closed)
	}
	return b.ReadCloser.Close()
}

type h3BodyResponse struct {
	response *http.Response
	err      error
}

func TestXHTTPH3StreamBodyRetryOwnership(t *testing.T) {
	for _, outcome := range []string{"success", "response-close", "cancel", "final-failure"} {
		t.Run(outcome, func(t *testing.T) {
			pending, resume := make(chan struct{}), make(chan struct{})
			finalError := errors.New("final replacement dial failure")
			f := newH3BodyFixture(t, func(generation int, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				if generation == 1 {
					<-r.Context().Done()
					return
				}
				// Flush every chunk so an open stream can be checked before EOF.
				buf := make([]byte, 1024)
				for {
					n, e := r.Body.Read(buf)
					if n > 0 {
						if _, err := w.Write(buf[:n]); err != nil {
							return
						}
						w.(http.Flusher).Flush()
					}
					if e != nil {
						return
					}
				}
			}, func(ctx context.Context, n int) error {
				if n != 2 {
					return nil
				}
				close(pending)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-resume:
					if outcome == "final-failure" {
						return finalError
					}
					return nil
				}
			})
			prime, _ := http.NewRequest(http.MethodOptions, f.target, nil)
			first, err := f.transport.RoundTrip(prime)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Body.Close()
			old := carrierReceive(t, f.accepted)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			selected := make(chan struct{})
			senderDone := make(chan error, 1)
			var selections atomic.Int32
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				GotConn: func(httptrace.GotConnInfo) {
					if selections.Add(1) == 1 {
						close(selected)
					}
				},
				WroteRequest: func(info httptrace.WroteRequestInfo) { senderDone <- info.Err },
			})
			pr, pw := io.Pipe()
			defer pw.Close()
			body := &h3CountedStream{ReadCloser: pr, closed: make(chan struct{})}
			request, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.target, body)
			result := make(chan h3BodyResponse, 1)
			go func() { resp, e := f.transport.RoundTrip(request); result <- h3BodyResponse{resp, e} }()
			carrierReceive(t, selected)
			f.shutdown(t, old)
			carrierReceive(t, pending)
			if body.closes.Load() != 0 || body.reads.Load() != 0 || old.requests.Load() != 1 {
				t.Fatalf("unsent retry did not preserve untouched body: closes=%d reads=%d requests=%d", body.closes.Load(), body.reads.Load(), old.requests.Load())
			}
			if outcome == "cancel" {
				cancel()
			} else {
				close(resume)
			}
			got := carrierReceive(t, result)
			if outcome == "cancel" || outcome == "final-failure" {
				want := finalError
				if outcome == "cancel" {
					want = context.Canceled
				}
				if !errors.Is(got.err, want) {
					t.Fatal("wrong final error", got.err)
				}
				if _, err := pw.Write([]byte("must be released")); err == nil {
					t.Fatal("failed request left writer open")
				}
			} else {
				if got.err != nil {
					t.Fatal("safe retry", got.err)
				}
				resp := got.response
				defer resp.Body.Close()
				payload := []byte("original pipe remains writable after safe retry")
				written := make(chan error, 1)
				go func() { _, err := pw.Write(payload); written <- err }()
				reply := make([]byte, len(payload))
				if _, err := io.ReadFull(resp.Body, reply); err != nil || !bytes.Equal(reply, payload) {
					t.Fatal("retried stream data", err, string(reply))
				}
				if err := carrierReceive(t, written); err != nil {
					t.Fatal(err)
				}
				if body.closes.Load() != 0 {
					t.Fatal("open successful stream closed before EOF or response Close")
				}
				if outcome == "success" {
					pw.Close()
					if _, err := io.Copy(io.Discard, resp.Body); err != nil {
						t.Fatal(err)
					}
					if err := carrierReceive(t, senderDone); err != nil {
						t.Fatal("body sender", err)
					}
				} else {
					resp.Body.Close()
					carrierReceive(t, senderDone)
				}
				var closing sync.WaitGroup
				for range 16 {
					closing.Go(func() { resp.Body.Close() })
				}
				closing.Wait()
			}
			carrierReceive(t, body.closed)
			if n := body.closes.Load(); n != 1 {
				t.Fatal("underlying body Close count", n)
			}
			first.Body.Close()
			f.transport.Close()
			h3ReclaimBound(t, f.transport, 0, 0, 0)
			t.Logf("outcome=%s untouched_at_retry=true underlying_close=%d", outcome, body.closes.Load())
		})
	}
}

type h3ObservedRequest struct {
	marker string
	body   []byte
}

type h3ReplayObservations struct {
	mu       sync.Mutex
	requests []h3ObservedRequest
}

func (o *h3ReplayObservations) start(marker string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests = append(o.requests, h3ObservedRequest{marker: marker})
	return len(o.requests) - 1
}

func (o *h3ReplayObservations) record(index int, data []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests[index].body = append(o.requests[index].body, data...)
}

func (o *h3ReplayObservations) snapshot() []h3ObservedRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	requests := make([]h3ObservedRequest, len(o.requests))
	for i, request := range o.requests {
		requests[i] = h3ObservedRequest{marker: request.marker, body: bytes.Clone(request.body)}
	}
	return requests
}

// The verdict uses application requests and their observed bytes. A successful
// RoundTrip only means response headers arrived, and says nothing about replay.
func h3CheckNoReplay(requests []h3ObservedRequest, marker string, payload []byte) error {
	if len(requests) != 1 {
		return fmt.Errorf("application request count=%d, want 1", len(requests))
	}
	if requests[0].marker != marker {
		return fmt.Errorf("application request marker=%q, want %q", requests[0].marker, marker)
	}
	if !bytes.Equal(requests[0].body, payload) {
		return fmt.Errorf("application body=%q, want exactly %q", requests[0].body, payload)
	}
	return nil
}

func TestXHTTPH3StreamBodyPartialSendNotReplayed(t *testing.T) {
	for _, ordering := range []string{"reset-race", "headers-first"} {
		t.Run(ordering, func(t *testing.T) {
			marker := t.Name()
			chunks := []string{"chunk-1|distinct-prefix|", "chunk-2|distinct-suffix|"}
			payload := []byte(chunks[0] + chunks[1])
			var observed h3ReplayObservations
			received, reset := make(chan struct{}, 4), make(chan struct{})
			releaseReset := sync.OnceFunc(func() { close(reset) })
			defer releaseReset()
			f := newH3BodyFixture(t, func(_ int, w http.ResponseWriter, r *http.Request) {
				index := observed.start(r.Header.Get("X-Test-Request"))
				prefix := make([]byte, len(payload))
				n, err := io.ReadFull(r.Body, prefix)
				observed.record(index, prefix[:n])
				if err != nil {
					return
				}
				received <- struct{}{}
				// HTTPStream flushes implicit HTTP 200. Either headers or reset
				// may become visible first; neither outcome is evidence of replay.
				stream := w.(http3.HTTPStreamer).HTTPStream()
				if ordering == "headers-first" {
					select {
					case <-reset:
					case <-r.Context().Done():
						return
					}
				}
				stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
				stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
			}, nil)
			pr, pw := io.Pipe()
			defer pw.Close()
			body := &h3CountedStream{ReadCloser: pr, closed: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			senderDone := make(chan error, 4)
			var attempts atomic.Int32
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				GotConn:      func(httptrace.GotConnInfo) { attempts.Add(1) },
				WroteRequest: func(info httptrace.WroteRequestInfo) { senderDone <- info.Err },
			})
			request, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.target, body)
			request.Header.Set("X-Test-Request", marker)
			result := make(chan h3BodyResponse, 1)
			go func() { resp, err := f.transport.RoundTrip(request); result <- h3BodyResponse{resp, err} }()
			written := make(chan error, 1)
			go func() {
				for _, chunk := range chunks {
					if _, err := io.WriteString(pw, chunk); err != nil {
						written <- err
						return
					}
				}
				// Keep the writer open: this is a partially sent streaming body.
				written <- nil
			}()
			carrierReceive(t, received)
			if err := carrierReceive(t, written); err != nil {
				t.Fatal(err)
			}
			got := carrierReceive(t, result)
			terminal := got.err
			if got.err == nil {
				if got.response.StatusCode != http.StatusOK {
					t.Fatal("unexpected response", got.response.StatusCode)
				}
				releaseReset()
				readDone := make(chan error, 1)
				go func() { _, err := io.Copy(io.Discard, got.response.Body); readDone <- err }()
				terminal = carrierReceive(t, readDone)
				got.response.Body.Close()
			} else if ordering == "headers-first" {
				t.Fatal("request failed before the gated reset", got.err)
			}
			var rejected *http3.Error
			if !errors.As(terminal, &rejected) || rejected.ErrorCode != http3.ErrCodeRequestRejected {
				t.Fatal("expected request reset on RoundTrip or response body", terminal)
			}
			carrierReceive(t, body.closed)
			carrierReceive(t, senderDone)
			// Stop accepts and join all handlers before inspecting the complete
			// request log, including a potential late second application request.
			f.close()
			requests := observed.snapshot()
			if err := h3CheckNoReplay(requests, marker, payload); err != nil {
				t.Fatal("streaming replay or incorrect application data", err)
			}
			if attempts.Load() != 1 || f.dials.Load() != 1 || body.closes.Load() != 1 {
				t.Fatal("unexpected physical attempt or cleanup", attempts.Load(), f.dials.Load(), body.closes.Load())
			}
			t.Logf("ordering=%s response_headers=%t application_requests=1 physical_attempts=1 dials=1 marker=%q bytes=%q underlying_close=1", ordering, got.err == nil, marker, requests[0].body)
		})
	}
}

func TestXHTTPH3StreamBodyReplayOracleNegativeControl(t *testing.T) {
	for _, duplicate := range []string{"request", "body"} {
		t.Run(duplicate, func(t *testing.T) {
			marker := t.Name()
			payload := []byte("chunk-1|chunk-2|chunk-3|")
			var observed h3ReplayObservations
			f := newH3BodyFixture(t, func(_ int, w http.ResponseWriter, r *http.Request) {
				index := observed.start(r.Header.Get("X-Test-Request"))
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error("control request body", err)
					return
				}
				observed.record(index, data)
				w.WriteHeader(http.StatusOK)
			}, nil)
			count, sent := 2, payload
			if duplicate == "body" {
				count, sent = 1, bytes.Repeat(payload, 2)
			}
			for range count {
				request, _ := http.NewRequest(http.MethodPost, f.target, io.NopCloser(bytes.NewReader(sent)))
				request.Header.Set("X-Test-Request", marker)
				resp, err := f.transport.RoundTrip(request)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, resp.Body); err != nil {
					resp.Body.Close()
					t.Fatal(err)
				}
				resp.Body.Close()
			}
			f.close()
			requests := observed.snapshot()
			if len(requests) != count || f.dials.Load() != 1 {
				t.Fatal("control did not execute its intended requests", len(requests), f.dials.Load())
			}
			for _, request := range requests {
				if request.marker != marker || !bytes.Equal(request.body, sent) {
					t.Fatal("control application observation", request)
				}
			}
			if err := h3CheckNoReplay(requests, marker, payload); err == nil {
				t.Fatal("oracle accepted deliberately duplicated application traffic")
			} else {
				t.Logf("negative_control=%s replay_detected=true requests=%d dials=1 reason=%v", duplicate, len(requests), err)
			}
		})
	}
}
