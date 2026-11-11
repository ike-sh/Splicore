//go:build with_quic

package xhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func h3ReclaimAwait(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("physical resource state did not converge")
		}
		time.Sleep(time.Millisecond)
	}
}

func h3ReclaimBound(t *testing.T, h *h3Transport, sockets, carriers, refs int) {
	t.Helper()
	h3ReclaimAwait(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		n := 0
		for c := range h.carriers {
			if c.refs < 0 {
				t.Fatal("negative physical lease count")
			}
			n += c.refs
		}
		return len(h.sockets) == sockets && len(h.carriers) == carriers && n == refs
	})
}

func h3ReclaimGoroutines() int {
	buf := make([]byte, 64<<10)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			count := 0
			for stack := range bytes.SplitSeq(buf[:n], []byte("\n\n")) {
				if bytes.Contains(stack, []byte("github.com/apernet/quic-go")) {
					count++
				}
			}
			return count
		}
		buf = make([]byte, 2*len(buf))
	}
}

// The same Client stays alive through every retry. The origin cache retains
// exactly one carrier, independent of the number of historical retries.
func TestXHTTPH3ReclamationScale(t *testing.T) {
	for _, cycles := range []int{1, 8, 32, 100} {
		t.Run(strconv.Itoa(cycles), func(t *testing.T) {
			cl, front := h3RetryFixture(t, "packet-up", nil)
			before := h3ReclaimGoroutines()
			probe := h3ReclaimTrackClient(t, cl)
			h := probe.h
			for i := range cycles {
				front.reject.Store(true)
				c, s := h3DialSession(t, cl)
				if i == 0 {
					front.connection(t)
				}
				front.connection(t)
				if h != s.download.transport.(*h3Transport) {
					t.Fatal("scale changed the fixed transport context")
				}
				exchange(t, c, []byte("bounded retry "+strconv.Itoa(i)))
				c.Close()
				h3AwaitTerminal(t, s)
				h3ReclaimBound(t, h, 1, 1, 0)
				packets := probe.snapshot()
				for _, old := range packets[:len(packets)-1] {
					if err := probe.retired(old); err != nil {
						t.Fatal("retired socket ownership", err)
					}
				}
			}
			// A normal operation must reuse the retained connection with no dial.
			c, s := h3DialSession(t, cl)
			exchange(t, c, []byte("cached carrier after scale"))
			select {
			case <-front.accepted:
				t.Fatal("healthy cache was not reused")
			default:
			}
			c.Close()
			h3AwaitTerminal(t, s)
			h3ReclaimBound(t, h, 1, 1, 0)
			h3ReclaimAwait(t, func() bool { return h3ReclaimGoroutines() <= before+16 })
			h.mu.Lock()
			current, idle, active, refs := len(h.sockets), 0, 0, 0
			for carrier := range h.carriers {
				refs += carrier.refs
				if carrier.refs == 0 {
					idle++
				} else {
					active++
				}
			}
			h.mu.Unlock()
			packets := probe.snapshot()
			created, open := len(packets), 0
			for _, packet := range packets {
				select {
				case <-packet.closeDone:
				default:
					open++
				}
			}
			if created != cycles+1 || open != 1 {
				t.Fatal("retry dial or real UDP ownership count", created, open)
			}
			t.Logf("retries=%d created=%d current=%d idle=%d active=%d request_refs=%d UDP=%d goroutines=%d quic_goroutines=%d", cycles, created, current, idle, active, refs, open, runtime.NumGoroutine(), h3ReclaimGoroutines())
			cl.Close()
			h3ReclaimBound(t, h, 0, 0, 0)
			for _, packet := range packets {
				if err := probe.retired(packet); err != nil {
					t.Fatal("owner Close retained socket ownership", err)
				}
			}
			probe.log(t)
			t.Log("owner_close_current=0 owner_close_idle=0 owner_close_active=0 owner_close_UDP=0")
		})
	}
}

// A and B are detached from the cache but still carry live response bodies.
// Closing one C session, then B, then A must leave the other users intact.
func TestXHTTPH3ReclamationSharedProtection(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	a, sa := h3DialSession(t, cl)
	pa := front.connection(t)
	front.reject.Store(true)
	b, sb := h3DialSession(t, cl)
	pb := front.connection(t)
	front.reject.Store(true)
	c, sc := h3DialSession(t, cl)
	pc := front.connection(t)
	d, sd := h3DialSession(t, cl)
	h := sc.download.transport.(*h3Transport)
	oldA := h3RetrySocket(t, h, pa)
	oldB := h3RetrySocket(t, h, pb)
	h3RetrySocket(t, h, pc)
	h3ReclaimBound(t, h, 3, 3, 4)
	for _, q := range []net.Conn{a, b, c, d} {
		exchange(t, q, []byte("all live"))
	}
	d.Close()
	h3AwaitTerminal(t, sd)
	h3ReclaimBound(t, h, 3, 3, 3)
	b.Close()
	h3AwaitTerminal(t, sb)
	h3ReclaimBound(t, h, 2, 2, 2)
	h3ReclaimRetiredSocket(t, h, oldB)
	exchange(t, a, []byte("A survives B retirement"))
	exchange(t, c, []byte("C survives B retirement"))
	a.Close()
	h3AwaitTerminal(t, sa)
	h3ReclaimBound(t, h, 1, 1, 1)
	h3ReclaimRetiredSocket(t, h, oldA)
	exchange(t, c, []byte("C survives A retirement"))
	e, se := h3DialSession(t, cl)
	exchange(t, e, []byte("C still cached"))
	select {
	case <-front.accepted:
		t.Fatal("C reuse redialed")
	default:
	}
	h3RetryClose(t, h, pc)
	h3AwaitTerminal(t, sc)
	h3AwaitTerminal(t, se)
	h3ReclaimBound(t, h, 0, 0, 0)
}

func TestXHTTPH3ReclamationSharedRetiredCarrier(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	a, sa := h3DialSession(t, cl)
	old := front.connection(t)
	h := sa.download.transport.(*h3Transport)
	oldSocket := h3RetrySocket(t, h, old)
	b, sb := h3DialSession(t, cl)
	front.reject.Store(true)
	c, sc := h3DialSession(t, cl)
	front.connection(t)
	h3ReclaimBound(t, h, 2, 2, 3)
	a.Close()
	h3AwaitTerminal(t, sa)
	h3ReclaimBound(t, h, 2, 2, 2)
	exchange(t, b, []byte("second user keeps uncached carrier alive"))
	exchange(t, c, []byte("cached carrier also remains healthy"))
	b.Close()
	h3AwaitTerminal(t, sb)
	h3ReclaimBound(t, h, 1, 1, 1)
	h3ReclaimRetiredSocket(t, h, oldSocket)
	exchange(t, c, []byte("last old user released only its own carrier"))
	c.Close()
	h3AwaitTerminal(t, sc)
	h3ReclaimBound(t, h, 1, 1, 0)
}

func TestXHTTPH3ReclamationRetryBudget(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			cl, front := h3RetryFixture(t, mode, nil)
			front.rejectEvery.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if c, err := cl.DialContext(ctx); err == nil {
				c.Close()
				t.Fatal("rejected request succeeded")
			}
			want := 2
			if mode == "stream-one" {
				want = 1
			}
			for range want {
				front.connection(t)
			}
			select {
			case <-front.accepted:
				t.Fatal("request exceeded safe physical retry budget")
			default:
			}
			cl.pool.mu.Lock()
			h := cl.pool.entries[0].transport.(*h3Transport)
			cl.pool.mu.Unlock()
			h3ReclaimBound(t, h, 0, 0, 0)
			t.Logf("mode=%s physical_attempts=%d", mode, want)
		})
	}
}

func TestXHTTPH3ReclamationReplayBody(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	c, s := h3DialSession(t, cl)
	a := front.connection(t)
	h := s.download.transport.(*h3Transport)
	oldSocket := h3RetrySocket(t, h, a)
	payload := bytes.Repeat([]byte("replay-exactly-once"), 8192)
	front.reject.Store(true)
	exchange(t, c, payload)
	b := front.connection(t)
	h3ReclaimBound(t, h, 2, 2, 1)
	if a.Context().Err() != nil || b.Context().Err() != nil {
		t.Fatal("active A or cached B prematurely reclaimed")
	}
	exchange(t, c, []byte("GET stays on A, subsequent POST reuses B"))
	select {
	case <-front.accepted:
		t.Fatal("POST did not reuse B")
	default:
	}
	c.Close()
	h3AwaitTerminal(t, s)
	h3ReclaimBound(t, h, 1, 1, 0)
	h3ReclaimRetiredSocket(t, h, oldSocket)
}

func TestXHTTPH3ReclamationConcurrentBodyClose(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	e, err := cl.pool.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer cl.pool.release(e)
	r, _ := http.NewRequest(http.MethodOptions, cl.URL().String(), nil)
	resp, err := e.request(r)
	if err != nil {
		t.Fatal(err)
	}
	front.connection(t)
	front.connection(t)
	io.Copy(io.Discard, resp.Body)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { resp.Body.Close() })
	}
	wg.Wait()
	h3ReclaimBound(t, e.transport.(*h3Transport), 1, 1, 0)
}

func TestXHTTPH3ReclamationPendingClose(t *testing.T) {
	entered := make(chan struct{})
	cl, front := h3RetryFixture(t, "packet-up", func(ctx context.Context, n int) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	done := make(chan error, 1)
	go func() {
		c, err := cl.DialContext(context.Background())
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	carrierReceive(t, entered)
	closed := make(chan struct{})
	go func() { cl.Close(); close(closed) }()
	carrierReceive(t, closed)
	if carrierReceive(t, done) == nil {
		t.Fatal("pending request survived Close")
	}
	select {
	case <-front.accepted:
		t.Fatal("pending dial resurrected after shutdown")
	default:
	}
}

func TestXHTTPH3ReclamationCanceledRequestCache(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	e := h3RetryPrime(t, cl)
	peer := front.connection(t)
	h := e.transport.(*h3Transport)
	h.mu.Lock()
	cached := h.cached
	h.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { cancel() }})
	r, _ := http.NewRequestWithContext(ctx, http.MethodOptions, cl.URL().String(), nil)
	if resp, err := e.request(r); !errors.Is(err, context.Canceled) {
		if resp != nil {
			resp.Body.Close()
		}
		t.Fatal("request cancellation did not propagate", err)
	}
	h3ReclaimBound(t, h, 1, 1, 0)
	h.mu.Lock()
	same := h.cached == cached
	h.mu.Unlock()
	if !same || peer.Context().Err() != nil {
		t.Fatal("single request cancellation evicted healthy cache")
	}
	h3RetryPrime(t, cl)
	select {
	case <-front.accepted:
		t.Fatal("canceled request forced a redial")
	default:
	}
}

func TestXHTTPH3ReclamationLateSocketClose(t *testing.T) {
	cl, _ := h3RetryFixture(t, "packet-up", nil)
	original := cl.security.PacketSocket
	created := make(chan net.PacketConn, 1)
	cl.security.PacketSocket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, a, err := original(ctx)
		if err != nil {
			return p, a, err
		}
		created <- p
		<-ctx.Done()
		// Exercise an underlay completing with an owned socket after cancellation.
		return p, a, nil
	}
	done := make(chan error, 1)
	go func() {
		c, err := cl.DialContext(context.Background())
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	p := carrierReceive(t, created)
	closed := make(chan struct{})
	go func() { cl.Close(); close(closed) }()
	carrierReceive(t, closed)
	if carrierReceive(t, done) == nil {
		t.Fatal("late socket resurrected a closed carrier")
	}
	h3ReclaimClosedPacket(t, p)
}

func TestXHTTPH3ReclamationCanceledPendingDial(t *testing.T) {
	cl, _ := h3RetryFixture(t, "packet-up", nil)
	original := cl.security.PacketSocket
	created, release := make(chan net.PacketConn, 1), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	cl.security.PacketSocket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, a, err := original(ctx)
		if err != nil {
			return p, a, err
		}
		created <- p
		<-ctx.Done()
		<-release
		return p, a, nil
	}
	e, err := cl.pool.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer cl.pool.release(e)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, http.MethodOptions, cl.URL().String(), nil)
	done := make(chan error, 1)
	go func() { _, err := e.request(r); done <- err }()
	p := carrierReceive(t, created)
	cancel()
	if err := carrierReceive(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal("pending request cancellation", err)
	}
	unblock()
	h := e.transport.(*h3Transport)
	h3ReclaimBound(t, h, 0, 0, 0)
	closed := make(chan struct{})
	go func() { cl.Close(); close(closed) }()
	carrierReceive(t, closed)
	h3ReclaimClosedPacket(t, p)
}

// A deliberately unmanaged extra physical dial validates that the same socket
// and live-context oracle detects one retained unused connection before cleanup.
func TestXHTTPH3ReclamationNegativeControl(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	e := h3RetryPrime(t, cl)
	front.connection(t)
	h := e.transport.(*h3Transport)
	q, err := h.dial(context.Background(), "", h.TLSClientConfig, h.QUICConfig)
	if err != nil {
		t.Fatal(err)
	}
	peer := front.connection(t)
	h.mu.Lock()
	sockets, carriers := len(h.sockets), len(h.carriers)
	h.mu.Unlock()
	if sockets != 2 || carriers != 1 || q.Context().Err() != nil {
		t.Fatal("oracle missed intentional unused physical connection", sockets, carriers)
	}
	retained := h3RetrySocket(t, h, peer)
	if err := h3ReclaimSocketError(h, retained); err == nil {
		t.Fatal("oracle missed retained UDP ownership")
	}
	q.CloseWithError(0, "negative control cleanup")
	h3ReclaimBound(t, h, 1, 1, 0)
	h3ReclaimRetiredSocket(t, h, retained)
}

func TestXHTTPH3ReclamationGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	t.Run("retries", func(t *testing.T) {
		cl, front := h3RetryFixture(t, "packet-up", nil)
		for i := range 128 {
			front.reject.Store(true)
			c, s := h3DialSession(t, cl)
			if i == 0 {
				front.connection(t)
			}
			front.connection(t)
			exchange(t, c, []byte("goroutine reclamation"))
			c.Close()
			h3AwaitTerminal(t, s)
		}
	})
	h3ReclaimAwait(t, func() bool { return runtime.NumGoroutine() <= before+8 })
	t.Logf("goroutines before=%d after=%d retries=128 no forced GC", before, runtime.NumGoroutine())
}

// The default positive keepalive remains enabled. Trace activity on the
// reusable carrier while the retired carrier's owned packet socket is closed.
type h3ReclaimPacket struct {
	net.PacketConn
	writes atomic.Int64
	closed atomic.Bool
}

func (p *h3ReclaimPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	p.writes.Add(1)
	return p.PacketConn.WriteTo(b, a)
}
func (p *h3ReclaimPacket) Close() error { p.closed.Store(true); return p.PacketConn.Close() }

func TestXHTTPH3ReclamationKeepalive(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	original := cl.security.PacketSocket
	var mu sync.Mutex
	var packets []*h3ReclaimPacket
	cl.security.PacketSocket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, a, err := original(ctx)
		if err != nil {
			return p, a, err
		}
		cp := &h3ReclaimPacket{PacketConn: p}
		mu.Lock()
		packets = append(packets, cp)
		mu.Unlock()
		return cp, a, nil
	}
	var got atomic.Int32
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { got.Add(1) }})
	e := h3RetryPrime(t, cl)
	a, b := front.connection(t), front.connection(t)
	h := e.transport.(*h3Transport)
	if h.QUICConfig.KeepAlivePeriod <= 0 {
		t.Fatal("keepalive disabled")
	}
	h3ReclaimBound(t, h, 1, 1, 0)
	mu.Lock()
	old, cached := packets[0], packets[1]
	mu.Unlock()
	if !old.closed.Load() || cached.closed.Load() {
		t.Fatal("incorrect packet owner closed")
	}
	oldWrites, cachedWrites := old.writes.Load(), cached.writes.Load()
	// Two keepalive periods make the closed-vs-cached observation explicit.
	timer := time.NewTimer(2*h.QUICConfig.KeepAlivePeriod + time.Second)
	defer timer.Stop()
	<-timer.C
	if old.writes.Load() != oldWrites || cached.writes.Load() <= cachedWrites || b.Context().Err() != nil || a.Context().Err() == nil {
		t.Fatal("retired traffic or missing healthy keepalive", old.writes.Load()-oldWrites, cached.writes.Load()-cachedWrites)
	}
	r, _ := http.NewRequestWithContext(ctx, http.MethodOptions, cl.URL().String(), nil)
	resp, err := e.request(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.Load() != 1 {
		t.Fatal("cached request did not complete")
	}
	t.Logf("retired_packet_delta=%d cached_packet_delta=%d retired_closed=true healthy_reused=true", old.writes.Load()-oldWrites, cached.writes.Load()-cachedWrites)
}
