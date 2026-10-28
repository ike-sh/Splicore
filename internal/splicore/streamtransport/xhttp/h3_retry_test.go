//go:build with_quic

package xhttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// The front rejects a request before processing any HTTP headers or body. The
// real quic-go Transport handles H3_REQUEST_REJECTED and chooses a new physical
// connection; the production Listener still handles every accepted XHTTP leg.
type h3RetryFront struct {
	reject      atomic.Bool
	rejectEvery atomic.Bool
	accepted    chan *h3RetryPeer
}

func h3RetryFixture(t *testing.T, mode string, socketGate func(context.Context, int) error) (*Client, *h3RetryFront) {
	t.Helper()
	backendClient, backend, _ := h3Fixture(t, cfg.Config{Kind: "xhttp"})
	backendClient.Close()
	st, ct := tlsPair(t)
	st.NextProtos, ct.NextProtos = []string{"h3"}, []string{"h3"}
	p, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: p}
	ql, err := tr.Listen(st, h3QUICConfig(true, 0))
	if err != nil {
		tr.Close()
		p.Close()
		t.Fatal(err)
	}
	f := &h3RetryFront{accepted: make(chan *h3RetryPeer, 128)}
	f.reject.Store(true)
	srv := &http3.Server{Handler: backend}
	ready := make(chan *Client, 1)
	defer close(ready)
	var workers sync.WaitGroup
	workers.Go(func() {
		client := <-ready
		if client == nil {
			return
		}
		for {
			q, err := ql.Accept(context.Background())
			if err != nil {
				return
			}
			target, err := h3RetryCapture(client, q)
			if err != nil {
				t.Error("capture retry connection", err)
				q.CloseWithError(0, "capture failed")
				continue
			}
			f.accepted <- target
			workers.Go(func() {
				hc, err := srv.NewRawServerConn(q)
				if err != nil {
					return
				}
				workers.Go(func() {
					for {
						s, err := q.AcceptUniStream(context.Background())
						if err != nil {
							return
						}
						workers.Go(func() { hc.HandleUnidirectionalStream(s) })
					}
				})
				for {
					s, err := q.AcceptStream(context.Background())
					if err != nil {
						return
					}
					if f.rejectEvery.Load() || f.reject.Swap(false) {
						s.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
						s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
						continue
					}
					workers.Go(func() { hc.HandleRequestStream(s) })
				}
			})
		}
	})
	t.Cleanup(func() {
		ql.Close()
		tr.Close()
		p.Close()
		backend.Close()
		workers.Wait()
	})
	var dials atomic.Int32
	cl, err := NewClient(func(context.Context, string, string) (net.Conn, error) {
		t.Error("HTTP/3 attempted TCP fallback")
		return nil, net.ErrClosed
	}, ql.Addr().String(), cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: mode, XMUX: &cfg.XMUX{MaxConnections: cfg.Range{Min: 1, Max: 1}}}}, Security{TLS: ct, PacketSocket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		index := int(dials.Add(1))
		if socketGate != nil {
			if err := socketGate(ctx, index); err != nil {
				return nil, nil, err
			}
		}
		cp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		return cp, ql.Addr(), err
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ready <- cl
	t.Cleanup(func() { cl.Close() })
	return cl, f
}

func (f *h3RetryFront) connection(t *testing.T) *h3RetryPeer {
	t.Helper()
	select {
	case q := <-f.accepted:
		return q
	case <-time.After(2 * time.Second):
		t.Fatal("physical retry connection not accepted")
		return nil
	}
}

func h3RetrySocket(t *testing.T, h *h3Transport, peer *h3RetryPeer) *h3Socket {
	t.Helper()
	if peer == nil || peer.transport != h || peer.socket == nil || peer.socket.conn == nil {
		t.Fatal("missing captured client socket for this transport")
	}
	return peer.socket
}

func h3RetryClose(t *testing.T, h *h3Transport, peer *h3RetryPeer) {
	t.Helper()
	h3RetrySocket(t, h, peer)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h3RetryCloseError(ctx, peer); err != nil {
		t.Fatal(err)
	}
}

func h3RetryDistinct(t *testing.T, a, b *h3RetryPeer) {
	t.Helper()
	if a.Conn == b.Conn || a.socket == b.socket || a.socket.conn == b.socket.conn {
		t.Fatal("retry requires two distinct physical connections")
	}
	t.Log("distinct QUIC connections", a.RemoteAddr(), b.RemoteAddr())
}

func h3RetryPrime(t *testing.T, cl *Client) *httpEntry {
	t.Helper()
	e, err := cl.pool.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer cl.pool.release(e)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "OPTIONS", cl.URL().String(), nil)
	resp, err := e.request(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return e
}

func TestXHTTPH3RetryConnectionOwnership(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	c, s := h3DialSession(t, cl)
	a, b := front.connection(t), front.connection(t)
	h3RetryDistinct(t, a, b)
	h := s.download.transport.(*h3Transport)
	exchange(t, c, []byte("B before retiring A"))
	h3RetryClose(t, h, a)
	exchange(t, c, []byte("B after retiring A"))
	if h.failed() || s.ctx.Err() != nil {
		t.Fatal("stale connection invalidated current carrier or session")
	}
	other, sibling := h3DialSession(t, cl)
	if sibling.download != s.download {
		t.Fatal("A failure invalidated reusable B pool entry")
	}
	exchange(t, other, []byte("B reused after A failure"))
	c.SetDeadline(time.Time{})
	read := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); read <- err }()
	h3RetryClose(t, h, b)
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("current B failure returned successful Read")
		}
	case <-time.After(time.Second):
		t.Fatal("B failure did not terminate session without local Close")
	}
	h3AwaitTerminal(t, s)
	h3AwaitTerminal(t, sibling)
	if h.failed() {
		t.Fatal("B failure retired reusable HTTP/3 transport")
	}
	h3AssertLeases(t, s.download, 0)
	replacement, next := h3DialSession(t, cl)
	exchange(t, replacement, []byte("new physical carrier after B failure"))
	current := front.connection(t)
	if next.download != s.download || current == b {
		t.Fatal("HTTP/3 did not replace failed B within the same transport")
	}
	t.Log("A close: B survives; B data: PASS; B close: automatic session termination")
}

func TestXHTTPH3RetryThreeConnections(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	// quic-go permits one retry per RoundTrip. Two successive real requests
	// exercise A -> B -> C without inventing a third library retry attempt.
	entry := h3RetryPrime(t, cl)
	a, b := front.connection(t), front.connection(t)
	front.reject.Store(true)
	c, s := h3DialSession(t, cl)
	current := front.connection(t)
	h3RetryDistinct(t, a, b)
	h3RetryDistinct(t, b, current)
	h := s.download.transport.(*h3Transport)
	if s.download != entry {
		t.Fatal("retry chain did not reuse original pool entry")
	}
	exchange(t, c, []byte("C before old connections close"))
	for _, stale := range []*h3RetryPeer{a, b} {
		h3RetryClose(t, h, stale)
		exchange(t, c, []byte("C survives another superseded connection"))
		if h.failed() {
			t.Fatal("stale connection retired C")
		}
	}
	h3RetryClose(t, h, current)
	h3AwaitTerminal(t, s)
	t.Log("real A -> B -> C; A and B close: C survives; C close: session terminates")
}

func TestXHTTPH3RetrySharedConnection(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	aConn, aSession := h3DialSession(t, cl)
	a := front.connection(t)
	exchange(t, aConn, []byte("session remaining on A"))
	front.reject.Store(true)
	bConn, bSession := h3DialSession(t, cl)
	b := front.connection(t)
	h3RetryDistinct(t, a, b)
	if aSession.download != bSession.download {
		t.Fatal("sessions did not share the retried pool entry")
	}
	exchange(t, bConn, []byte("retried session now on B"))
	h := bSession.download.transport.(*h3Transport)
	h3RetryClose(t, h, a)
	h3AwaitTerminal(t, aSession)
	exchange(t, bConn, []byte("B survives failure of A's dependent session"))
	if bSession.ctx.Err() != nil || h.failed() {
		t.Fatal("A-dependent termination contaminated B")
	}
	h3AssertLeases(t, bSession.download, 1)
	h3RetryClose(t, h, b)
	h3AwaitTerminal(t, bSession)
}

func TestXHTTPH3RetriedPoolStreamOneBackpressure(t *testing.T) {
	cl, front := h3RetryFixture(t, "stream-one", nil)
	entry := h3RetryPrime(t, cl)
	a, b := front.connection(t), front.connection(t)
	h3RetryDistinct(t, a, b)
	c, s := h3DialSession(t, cl)
	if s.download != entry {
		t.Fatal("stream-one did not use retried B pool entry")
	}
	exchange(t, c, []byte("stream-one on retried B"))
	h := entry.transport.(*h3Transport)
	h3RetryClose(t, h, a)
	exchange(t, c, []byte("stream-one B still healthy"))
	writes := h3BlockedWriters(t, c, 3)
	start := time.Now()
	h3RetryClose(t, h, b)
	h3CheckWriters(t, writes, start)
	h3AwaitTerminal(t, s)
	h3AssertLeases(t, entry, 0)
	entry.pool.mu.Lock()
	retired := entry.retired
	entry.pool.mu.Unlock()
	if retired {
		t.Fatal("B failure retired the whole reusable HTTP/3 transport")
	}
	replacement, next := h3DialSession(t, cl)
	exchange(t, replacement, []byte("replacement after B terminal failure"))
	current := front.connection(t)
	if next.download != entry || current == b {
		t.Fatal("HTTP/3 did not replace failed physical B")
	}
}

func TestXHTTPH3RetryCancellation(t *testing.T) {
	for _, event := range []string{"caller-cancel", "client-close", "stale-close", "current-close"} {
		t.Run(event, func(t *testing.T) {
			entered, proceed := make(chan struct{}), make(chan struct{})
			cl, front := h3RetryFixture(t, "packet-up", func(ctx context.Context, index int) error {
				if index == 2 {
					close(entered)
					select {
					case <-proceed:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				conn net.Conn
				err  error
			}
			done := make(chan result, 1)
			go func() { c, err := cl.DialContext(ctx); done <- result{c, err} }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("retry never reached B dial")
			}
			a := front.connection(t)
			cl.mu.Lock()
			var s *clientSession
			for pending := range cl.sessions {
				s = pending
			}
			cl.mu.Unlock()
			if s == nil {
				t.Fatal("missing pending production session")
			}
			h := s.download.transport.(*h3Transport)
			closed := make(chan struct{})
			switch event {
			case "caller-cancel":
				cancel()
			case "client-close":
				go func() { cl.Close(); close(closed) }()
				select {
				case <-s.ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("local Close did not cancel pending session")
				}
			case "stale-close":
				h3RetryClose(t, h, a)
			}
			close(proceed)
			var r result
			select {
			case r = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("retry/cancellation retained DialContext")
			}
			if event == "caller-cancel" || event == "client-close" {
				if r.err == nil {
					r.conn.Close()
					t.Fatal("canceled retry resurrected a session")
				}
			} else {
				if r.err != nil {
					t.Fatal("stale failure prevented safe retry", r.err)
				}
				t.Cleanup(func() { r.conn.Close() })
				b := front.connection(t)
				exchange(t, r.conn, []byte("B after concurrent retry event"))
				h3RetryClose(t, h, b)
			}
			h3AwaitTerminal(t, s)
			if event == "client-close" {
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("local Close retained retry workers")
				}
			}
		})
	}
}

type h3CountedContext struct {
	context.Context
	watches atomic.Int32
}

func (*h3CountedContext) Value(any) any { return nil }

func (c *h3CountedContext) AfterFunc(f func()) func() bool {
	c.watches.Add(1)
	var once sync.Once
	decrement := func() { once.Do(func() { c.watches.Add(-1) }) }
	stop := context.AfterFunc(c.Context, func() { defer decrement(); f() })
	return func() bool {
		stopped := stop()
		if stopped {
			decrement()
		}
		return stopped
	}
}

func TestXHTTPH3RetryWatcherBounds(t *testing.T) {
	a, cancelA := context.WithCancel(context.Background())
	b, cancelB := context.WithCancel(context.Background())
	c, cancelC := context.WithCancelCause(context.Background())
	defer cancelA()
	defer cancelB()
	defer cancelC(net.ErrClosed)
	aCount, bCount, cCount := &h3CountedContext{Context: a}, &h3CountedContext{Context: b}, &h3CountedContext{Context: c}
	failed := make(chan error, 1)
	w := &h3RequestWatch{fail: func(err error) { failed <- err }}
	defer w.close()
	for range 1000 {
		w.selectAttempt(aCount)
		w.selectAttempt(bCount)
	}
	w.selectAttempt(cCount)
	if err := w.commit(); err != nil {
		t.Fatal(err)
	}
	if aCount.watches.Load() != 0 || bCount.watches.Load() != 0 || cCount.watches.Load() != 1 {
		t.Fatal("attempt watchers were accumulated rather than transferred")
	}
	closed := &h3RequestWatch{fail: func(err error) { t.Error("closed watcher fired", err) }}
	closed.selectAttempt(cCount)
	if err := closed.commit(); err != nil {
		t.Fatal(err)
	}
	closed.close()
	if cCount.watches.Load() != 1 {
		t.Fatal("response close did not unregister its connection watcher")
	}
	cancelA()
	cancelB()
	select {
	case err := <-failed:
		t.Fatal("superseded attempt retained terminal authority", err)
	default:
	}
	terminal := errors.New("current C terminated")
	cancelC(terminal)
	select {
	case err := <-failed:
		// The counting context hides values to exercise context.AfterFunc's
		// registration hook, so Cause intentionally falls back to Err here.
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("current attempt lost terminal authority")
	}
	w.close()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.attempt != nil || w.stopConn != nil || w.stopRequest != nil {
		t.Fatal("closed watch retained attempt or callbacks")
	}
}

func TestXHTTPH3RetryCommitCloseRace(t *testing.T) {
	for range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		var failures atomic.Int32
		w := &h3RequestWatch{fail: func(error) { failures.Add(1) }}
		w.selectAttempt(context.Background())
		w.selectAttempt(ctx)
		var workers sync.WaitGroup
		workers.Go(func() { _ = w.commit() })
		workers.Go(w.close)
		workers.Go(cancel)
		workers.Go(func() { w.selectAttempt(context.Background()) })
		workers.Wait()
		w.close()
		if err := w.commit(); err == nil {
			t.Fatal("closed watcher was resurrected")
		}
		if failures.Load() > 1 {
			t.Fatal("attempt invoked terminal callback repeatedly")
		}
	}
}

func TestXHTTPH3RetryParallel(t *testing.T) {
	for i := range 4 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			TestXHTTPH3RetryConnectionOwnership(t)
		})
	}
}

func TestXHTTPH3RetryResourceCleanup(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := range 12 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			cl, front := h3RetryFixture(t, "packet-up", nil)
			probe := h3ReclaimTrackClient(t, cl)
			c, s := h3DialSession(t, cl)
			a, b := front.connection(t), front.connection(t)
			h := s.download.transport.(*h3Transport)
			exchange(t, c, []byte("resource probe before retry retirement"))
			h3RetryClose(t, h, a)
			exchange(t, c, []byte("resource probe after retry retirement"))
			h3RetryClose(t, h, b)
			h3AwaitTerminal(t, s)
			cl.Close()
			h.mu.Lock()
			retained := len(h.sockets)
			h.mu.Unlock()
			if retained != 0 || len(cl.sessions) != 0 || len(cl.pool.entries) != 0 {
				t.Fatal("retry retained sockets, sessions or pool entries")
			}
			h3ReclaimBound(t, h, 0, 0, 0)
			for _, p := range probe.snapshot() {
				h3ReclaimAwait(t, func() bool { return probe.retired(p) == nil })
			}
		})
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before+8 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+8 {
		t.Fatal("retry workers retained after fixture/session cleanup", before, after)
	}
	t.Log("12 real retry lifecycles: no retained sessions/pool entries/sockets; goroutines", before, runtime.NumGoroutine())
}
