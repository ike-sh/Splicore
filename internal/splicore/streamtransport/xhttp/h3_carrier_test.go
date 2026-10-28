//go:build with_quic

package xhttp

import (
	"context"
	"fmt"
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

type h3CarrierResult struct {
	conn net.Conn
	err  error
}

// Every initial request reaches A before any rejection. Rejected requests
// admit independent replacement dials; gates delay socket creation, not cache
// acquisition. The last admitted replacement C completes first. Earlier B
// replacements complete later and can serve their original in-flight requests,
// although new requests still acquire C from quic-go's cache.
type h3CarrierFixture struct {
	client   *Client
	requests chan *quic.Stream
	accepted chan *h3RetryPeer
	entered  []chan struct{}
	release  []chan struct{}
	once     []sync.Once
	dials    atomic.Int32
	carriers sync.Map // actual decoded session ID -> server QUIC connection
	mu       sync.Mutex
	sockets  []net.PacketConn
	stop     func()
}

func newH3CarrierFixture(t *testing.T, count int, mode string) *h3CarrierFixture {
	t.Helper()
	unused, backend, _ := h3Fixture(t, cfg.Config{Kind: "xhttp"})
	unused.Close()
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
	f := &h3CarrierFixture{
		requests: make(chan *quic.Stream, count), accepted: make(chan *h3RetryPeer, 32),
		entered: make([]chan struct{}, count-1), release: make([]chan struct{}, count-1), once: make([]sync.Once, count-1),
	}
	for i := range f.release {
		f.release[i], f.entered[i] = make(chan struct{}), make(chan struct{})
	}
	ready := make(chan *Client, 1)
	defer close(ready)
	var workers sync.WaitGroup
	workers.Go(func() {
		client := <-ready
		if client == nil {
			return
		}
		index := 0
		for {
			q, err := ql.Accept(context.Background())
			if err != nil {
				return
			}
			index++
			initial := index == 1
			target, err := h3RetryCapture(client, q)
			if err != nil {
				t.Error("capture carrier connection", err)
				q.CloseWithError(0, "capture failed")
				continue
			}
			f.accepted <- target
			workers.Go(func() {
				server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Test-Carrier", fmt.Sprintf("%p", q))
					if sid, _, err := parseEnvelope(r, backend.config); err == nil && sid != "" && r.Method == http.MethodGet {
						f.carriers.Store(sid, q)
					}
					backend.ServeHTTP(w, r)
				})}
				hc, err := server.NewRawServerConn(q)
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
					if initial {
						f.requests <- s
						continue
					}
					workers.Go(func() { hc.HandleRequestStream(s) })
				}
			})
		}
	})
	var stop sync.Once
	f.stop = func() {
		stop.Do(func() {
			for i := range f.release {
				f.unblock(i)
			}
			f.client.Close()
			ql.Close()
			tr.Close()
			p.Close()
			backend.Close()
			workers.Wait()
		})
	}
	cl, err := NewClient(func(context.Context, string, string) (net.Conn, error) {
		t.Error("unexpected TCP fallback")
		return nil, net.ErrClosed
	}, ql.Addr().String(), cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: mode, XMUX: &cfg.XMUX{MaxConnections: cfg.Range{Min: 1, Max: 1}}}}, Security{TLS: ct, PacketSocket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		n := int(f.dials.Add(1))
		if n >= 2 && n <= count {
			i := n - 2
			close(f.entered[i])
			select {
			case <-f.release[i]:
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		cp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			f.mu.Lock()
			f.sockets = append(f.sockets, cp)
			f.mu.Unlock()
		}
		return cp, ql.Addr(), err
	}}, nil)
	if err != nil {
		ql.Close()
		tr.Close()
		p.Close()
		t.Fatal(err)
	}
	f.client = cl
	ready <- cl
	t.Cleanup(f.stop)
	return f
}

func (f *h3CarrierFixture) unblock(i int) { f.once[i].Do(func() { close(f.release[i]) }) }

func carrierReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("carrier coordination event missing")
		var zero T
		return zero
	}
}

func h3CarrierSession(t *testing.T, cl *Client, c net.Conn) *clientSession {
	t.Helper()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for s := range cl.sessions {
		if s.app == c.(*logicalConn).Conn {
			return s
		}
	}
	t.Fatal("missing carrier session")
	return nil
}

func (f *h3CarrierFixture) assertSession(t *testing.T, s *clientSession, q *h3RetryPeer) {
	t.Helper()
	actual, ok := f.carriers.Load(s.id)
	if !ok || actual != q.Conn {
		t.Fatal("successful GET carrier differs from physical connection", s.id, actual, q)
	}
}

// A real request identifies the server's exact QUIC object in its response;
// independently check the client cache's captured physical socket identity.
func h3AssertCachedCarrier(t *testing.T, f *h3CarrierFixture, e *httpEntry, q *h3RetryPeer) {
	t.Helper()
	r, _ := http.NewRequest(http.MethodOptions, f.client.URL().String(), nil)
	resp, err := e.request(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	h := e.transport.(*h3Transport)
	h.mu.Lock()
	cached := h.cached == q.socket.owner && h.sockets[q.socket]
	h.mu.Unlock()
	if !cached || resp.Header.Get("X-Test-Carrier") != fmt.Sprintf("%p", q.Conn) {
		t.Fatal("client cache and successful response did not identify C", resp.Header)
	}
	e.pool.mu.Lock()
	defer e.pool.mu.Unlock()
	if e.retired || len(e.pool.entries) != 1 {
		t.Fatal("healthy carrier retired or duplicated its transport entry")
	}
}

func h3ConcurrentCarriers(t *testing.T, count int) {
	t.Helper()
	f := newH3CarrierFixture(t, count, "packet-up")
	results := make([]chan h3CarrierResult, count)
	streams := make([]*quic.Stream, count)
	for i := range results {
		results[i] = make(chan h3CarrierResult, 1)
		go func() { c, err := f.client.DialContext(context.Background()); results[i] <- h3CarrierResult{c, err} }()
		streams[i] = carrierReceive(t, f.requests)
	}
	a := carrierReceive(t, f.accepted)
	for i, stream := range streams {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
		if i < count-1 {
			carrierReceive(t, f.entered[i])
		}
	}
	cResult := carrierReceive(t, results[count-1])
	if cResult.err != nil {
		t.Fatal(cResult.err)
	}
	c := carrierReceive(t, f.accepted)
	s := h3CarrierSession(t, f.client, cResult.conn)
	e := s.download
	h := e.transport.(*h3Transport)
	f.assertSession(t, s, c)
	exchange(t, cResult.conn, []byte("C before other candidates complete"))
	h3AssertCachedCarrier(t, f, e, c)
	late := make([]*h3RetryPeer, count-1)
	lateSessions := make([]*clientSession, count-1)
	lateConns := make([]net.Conn, count-1)
	for i := count - 2; i >= 0; i-- {
		f.unblock(i)
		r := carrierReceive(t, results[i])
		if r.err != nil {
			t.Fatal(r.err)
		}
		b := carrierReceive(t, f.accepted)
		late[i], lateConns[i] = b, r.conn
		lateSessions[i] = h3CarrierSession(t, f.client, r.conn)
		h3RetryDistinct(t, b, c)
		f.assertSession(t, lateSessions[i], b)
		exchange(t, r.conn, []byte("older request actually carried by late B"))
		h3AssertCachedCarrier(t, f, e, c)
	}
	before := f.dials.Load()
	h3RetryClose(t, h, a)
	for i, b := range late {
		h3RetryClose(t, h, b)
		h3AwaitTerminal(t, lateSessions[i])
		exchange(t, cResult.conn, []byte("C after a non-cached connection closes"))
		for j := i + 1; j < len(late); j++ {
			exchange(t, lateConns[j], []byte("another older carrier also survives"))
		}
		h3AssertCachedCarrier(t, f, e, c)
	}
	sibling, ss := h3DialSession(t, f.client)
	f.assertSession(t, ss, c)
	exchange(t, sibling, []byte("fresh logical session reuses C"))
	if ss.download != e || f.dials.Load() != before {
		t.Fatal("non-carrier close forced a reconnect", before, f.dials.Load())
	}
	cResult.conn.SetDeadline(time.Time{})
	sibling.SetDeadline(time.Time{})
	reads := make(chan error, 2)
	go func() { _, err := cResult.conn.Read(make([]byte, 1)); reads <- err }()
	go func() { _, err := sibling.Read(make([]byte, 1)); reads <- err }()
	h3RetryClose(t, h, c)
	for range 2 {
		if err := carrierReceive(t, reads); err == nil {
			t.Fatal("C failure did not terminate dependent Read")
		} else if n, ok := err.(net.Error); ok && n.Timeout() {
			t.Fatal("deadline masked C failure", err)
		}
	}
	h3AwaitTerminal(t, s)
	h3AwaitTerminal(t, ss)
	h3AssertLeases(t, e, 0)
	replacement, next := h3DialSession(t, f.client)
	exchange(t, replacement, []byte("required replacement after actual C failure"))
	d := carrierReceive(t, f.accepted)
	f.assertSession(t, next, d)
	if next.download != e || d == c || f.dials.Load() != before+1 {
		t.Fatal("C failure did not replace exactly its physical cache connection")
	}
	t.Logf("C=%s; %d late carriers closed; no spurious reconnect %d->%d; C failure produced exactly one replacement", c.RemoteAddr(), len(late), before, before)
}

func TestXHTTPH3ConcurrentCarrierOwnership(t *testing.T) { h3ConcurrentCarriers(t, 2) }

func TestXHTTPH3ConcurrentCarrierCandidates(t *testing.T) { h3ConcurrentCarriers(t, 4) }

func TestXHTTPH3ConcurrentCarrierBackpressure(t *testing.T) {
	f := newH3CarrierFixture(t, 2, "stream-one")
	e, err := f.client.pool.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer f.client.pool.release(e)
	prime := func() <-chan error {
		done := make(chan error, 1)
		go func() {
			r, _ := http.NewRequest(http.MethodOptions, f.client.URL().String(), nil)
			resp, err := e.request(r)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			done <- err
		}()
		return done
	}
	one := prime()
	s1 := carrierReceive(t, f.requests)
	two := prime()
	s2 := carrierReceive(t, f.requests)
	a := carrierReceive(t, f.accepted)
	s1.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
	s1.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
	carrierReceive(t, f.entered[0])
	s2.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
	s2.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
	if err := carrierReceive(t, two); err != nil {
		t.Fatal(err)
	}
	c := carrierReceive(t, f.accepted)
	h3AssertCachedCarrier(t, f, e, c)
	f.unblock(0)
	if err := carrierReceive(t, one); err != nil {
		t.Fatal(err)
	}
	b := carrierReceive(t, f.accepted)
	h3RetryDistinct(t, b, c)
	h := e.transport.(*h3Transport)
	h3RetryClose(t, h, a)
	h3RetryClose(t, h, b)
	h3AssertCachedCarrier(t, f, e, c)
	conn, s := h3DialSession(t, f.client)
	exchange(t, conn, []byte("stream-one active on cached C"))
	if s.download != e || f.dials.Load() != 3 {
		t.Fatal("late B close retired C before stream-one")
	}
	writes := h3BlockedWriters(t, conn, 3)
	start := time.Now()
	h3RetryClose(t, h, c)
	h3CheckWriters(t, writes, start)
	h3AwaitTerminal(t, s)
}

func TestXHTTPH3ConcurrentCarrierCleanup(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := range 12 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			f := newH3CarrierFixture(t, 2, "packet-up")
			// Explicitly admit otherwise-unused candidates. The transport owns
			// their dedicated sockets even when the HTTP cache never owns them.
			f.unblock(0)
			e, err := f.client.pool.lease()
			if err != nil {
				t.Fatal(err)
			}
			h := e.transport.(*h3Transport)
			for range 3 {
				q, err := h.dial(context.Background(), "", h.TLSClientConfig, h.QUICConfig)
				if err != nil {
					t.Fatal(err)
				}
				if q.Context().Err() != nil {
					t.Fatal("candidate closed before explicit owner cleanup")
				}
				carrierReceive(t, f.accepted)
			}
			f.client.pool.release(e)
			f.mu.Lock()
			packets := append([]net.PacketConn(nil), f.sockets...)
			f.mu.Unlock()
			h.mu.Lock()
			var sockets []*h3Socket
			for socket := range h.sockets {
				sockets = append(sockets, socket)
			}
			h.mu.Unlock()
			f.stop()
			h.mu.Lock()
			retained := len(h.sockets)
			h.mu.Unlock()
			if retained != 0 || len(f.client.sessions) != 0 || len(f.client.pool.entries) != 0 {
				t.Fatal("candidate cleanup retained resources")
			}
			h3ReclaimBound(t, h, 0, 0, 0)
			for _, p := range packets {
				h3ReclaimClosedPacket(t, p)
			}
			for _, socket := range sockets {
				h3ReclaimRetiredSocket(t, h, socket)
			}
		})
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before+8 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	after := runtime.NumGoroutine()
	if after > before+8 {
		t.Fatal("candidate cleanup retained goroutines", before, after)
	}
	t.Log("12 explicit unused-candidate cleanup cycles; goroutines", before, after)
}
