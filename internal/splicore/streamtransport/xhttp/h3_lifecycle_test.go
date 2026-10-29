//go:build with_quic

package xhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

func h3DialSession(t *testing.T, cl *Client) (net.Conn, *clientSession) {
	t.Helper()
	c, err := cl.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for s := range cl.sessions {
		if s.app == c.(*logicalConn).Conn {
			return c, s
		}
	}
	t.Fatal("missing production session")
	return nil, nil
}

func h3SessionSocket(t *testing.T, s *clientSession) (*h3Transport, *h3Socket) {
	t.Helper()
	h := s.download.transport.(*h3Transport)
	h.mu.Lock()
	defer h.mu.Unlock()
	for p := range h.sockets {
		if p.conn != nil && p.conn.Context().Err() == nil {
			return h, p
		}
	}
	t.Fatal("missing established QUIC socket")
	return nil, nil
}

func h3AwaitTerminal(t *testing.T, s *clientSession) {
	t.Helper()
	select {
	case <-s.joined:
	case <-time.After(2 * time.Second):
		t.Fatal("session workers retained after terminal event")
	}
	s.client.mu.Lock()
	present := s.client.sessions[s]
	s.client.mu.Unlock()
	if present {
		t.Fatal("terminal session retained in registry")
	}
}

func h3AssertLeases(t *testing.T, e *httpEntry, want int) {
	t.Helper()
	e.pool.mu.Lock()
	defer e.pool.mu.Unlock()
	if e.active != want {
		t.Fatal("terminal session lease accounting", e.active, want)
	}
}

type h3WriteResult struct {
	n   int
	err error
}

func h3BlockedWriters(t *testing.T, c net.Conn, count int) []<-chan h3WriteResult {
	t.Helper()
	// The echo is not read. 32 MiB exceeds the QUIC stream and connection windows,
	// HTTP copy buffers and net.Pipe capacity. No network deadlines drive failure.
	c.SetDeadline(time.Time{})
	var done []<-chan h3WriteResult
	payload := make([]byte, 32<<20)
	for range count {
		ch := make(chan h3WriteResult, 1)
		go func() { n, err := c.Write(payload); ch <- h3WriteResult{n, err} }()
		done = append(done, ch)
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case r := <-done[0]:
		t.Fatal("large production H3 write did not backpressure", r)
	case <-timer.C:
	}
	return done
}

func h3CheckWriters(t *testing.T, done []<-chan h3WriteResult, start time.Time) {
	t.Helper()
	for _, ch := range done {
		select {
		case r := <-ch:
			if r.err == nil || r.n >= 32<<20 {
				t.Fatal("transport failure reported undelivered bytes as success", r)
			}
			if e, ok := r.err.(net.Error); ok && e.Timeout() {
				t.Fatal("deadline masked transport failure", r.err)
			}
			t.Logf("blocked Write: n=%d error=%v elapsed=%s", r.n, r.err, time.Since(start))
		case <-time.After(2 * time.Second):
			t.Fatal("terminal event retained blocked Write without local Close")
		}
	}
}

func TestXHTTPH3TerminalBackpressure(t *testing.T) {
	for _, event := range []string{"udp-fatal", "quic-application-close", "h3-close", "listener-close", "context-cancel", "local-close", "cancel-failure-race"} {
		t.Run(event, func(t *testing.T) {
			cl, l, _ := h3Fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "stream-one", XMUX: &cfg.XMUX{MaxConnections: cfg.Range{Min: 1, Max: 1}}}})
			a, sa := h3DialSession(t, cl)
			b, sb := h3DialSession(t, cl)
			exchange(t, a, []byte("backpressure subject alive"))
			exchange(t, b, []byte("same connection sibling alive"))
			b.SetDeadline(time.Time{})
			h, socket := h3SessionSocket(t, sa)
			_, other := h3SessionSocket(t, sb)
			if socket != other {
				t.Fatal("sessions did not share QUIC connection")
			}
			writes := h3BlockedWriters(t, a, 3)
			// Keep a simultaneous read pending on a dependent sibling, without draining
			// the backpressured response that establishes the original finding.
			read := make(chan error, 1)
			if event != "context-cancel" && event != "local-close" {
				go func() { _, err := b.Read(make([]byte, 1)); read <- err }()
			}
			start := time.Now()
			switch event {
			case "udp-fatal":
				socket.packet.Close()
			case "quic-application-close":
				socket.conn.CloseWithError(0x177, "lifecycle test")
			case "h3-close":
				l.carrierClose()
			case "listener-close":
				l.Close()
			case "context-cancel":
				sa.cancel(context.Canceled)
			case "local-close":
				a.Close()
			case "cancel-failure-race":
				var wg sync.WaitGroup
				wg.Go(func() { sa.cancel(context.Canceled) })
				wg.Go(func() { socket.packet.Close() })
				wg.Wait()
			}
			h3CheckWriters(t, writes, start)
			h3AwaitTerminal(t, sa)
			t.Log("session terminal cause", context.Cause(sa.ctx))
			if event == "context-cancel" || event == "local-close" {
				exchange(t, b, []byte("unrelated request survives session termination"))
				h3AssertLeases(t, sa.download, 1)
				if h.failed() {
					t.Fatal("single request termination invalidated whole connection")
				}
			} else {
				select {
				case err := <-read:
					if err == nil {
						t.Fatal("connection failure returned successful Read")
					}
					if e, ok := err.(net.Error); ok && e.Timeout() {
						t.Fatal("peer read only timed out")
					}
					t.Log("dependent Read", err, "QUIC cause", context.Cause(socket.conn.Context()))
				case <-time.After(2 * time.Second):
					t.Fatal("connection failure retained sibling Read")
				}
				h3AwaitTerminal(t, sb)
				h3AssertLeases(t, sa.download, 0)
				// Stream reset and CONNECTION_CLOSE are distinct peer events. A
				// reset may release I/O before the connection close packet arrives.
				select {
				case <-socket.conn.Context().Done():
				case <-time.After(time.Second):
					t.Fatal("transport did not observe definitive QUIC termination")
				}
				if h.failed() {
					t.Fatal("physical failure retired reusable HTTP/3 transport")
				}
			}
			// Concurrent later Close must be harmless after automatic termination.
			var closeWG sync.WaitGroup
			for range 8 {
				closeWG.Go(func() { a.Close() })
			}
			closeWG.Wait()
			cl.Close()
			l.Close()
			h.mu.Lock()
			retained := len(h.sockets)
			h.mu.Unlock()
			if retained != 0 {
				t.Fatal("transport retained socket", retained)
			}
			l.mu.Lock()
			defer l.mu.Unlock()
			if len(l.sessions) != 0 || l.pending != 0 || l.receiving != 0 {
				t.Fatal("server retained terminal resources")
			}
		})
	}
}

func TestXHTTPH3FailurePoolIsolation(t *testing.T) {
	cl, l, count := h3Fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "stream-one", XMUX: &cfg.XMUX{MaxConnections: cfg.Range{Min: 2, Max: 2}}}})
	a, sa := h3DialSession(t, cl)
	b, sb := h3DialSession(t, cl)
	exchange(t, a, []byte("connection A"))
	exchange(t, b, []byte("connection B"))
	if sa.download == sb.download || count.Load() != 2 {
		t.Fatal("two independent pooled connections required")
	}
	_, dead := h3SessionSocket(t, sa)
	writes := h3BlockedWriters(t, a, 1)
	start := time.Now()
	dead.packet.Close()
	h3CheckWriters(t, writes, start)
	h3AwaitTerminal(t, sa)
	h3AssertLeases(t, sa.download, 0)
	exchange(t, b, []byte("healthy B after A failure"))
	c, sc := h3DialSession(t, cl)
	exchange(t, c, []byte("new session on valid connection"))
	if sc.download != sa.download || count.Load() != 3 {
		t.Fatal("failed physical connection was not replaced within its reusable transport", count.Load())
	}
	_, replacement := h3SessionSocket(t, sc)
	if replacement.conn == dead.conn || replacement.conn.Context().Err() != nil {
		t.Fatal("new session reused failed physical connection")
	}
	exchange(t, b, []byte("B survives replacement connection"))
	cl.pool.mu.Lock()
	retired := sa.download.retired
	cl.pool.mu.Unlock()
	if retired {
		t.Fatal("physical failure retired the whole HTTP/3 transport")
	}
	cl.Close()
	l.Close()
	if len(cl.pool.entries) != 0 || len(cl.sessions) != 0 {
		t.Fatal("pool or session registry retained")
	}
}

func TestXHTTPH3RemoteStreamResetIsolation(t *testing.T) {
	st, ct := tlsPair(t)
	st.NextProtos = []string{"h3"}
	ct.NextProtos = []string{"h3"}
	p, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	streams := make(chan *http3.Stream, 4)
	srv := &http3.Server{TLSConfig: st, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		s := w.(http3.HTTPStreamer).HTTPStream()
		streams <- s
		defer s.Close()
		_, _ = io.Copy(s, r.Body)
	})}
	go srv.Serve(p)
	defer func() { srv.Close(); p.Close() }()
	var sockets atomic.Int32
	cl, err := NewClient(func(context.Context, string, string) (net.Conn, error) {
		t.Error("TCP fallback")
		return nil, net.ErrClosed
	}, p.LocalAddr().String(), cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "stream-one", XMUX: &cfg.XMUX{MaxConnections: cfg.Range{Min: 1, Max: 1}}}}, Security{TLS: ct, PacketSocket: func(context.Context) (net.PacketConn, net.Addr, error) {
		q, e := net.ListenPacket("udp4", "127.0.0.1:0")
		sockets.Add(1)
		return q, p.LocalAddr(), e
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	a, sa := h3DialSession(t, cl)
	reset := <-streams
	b, _ := h3DialSession(t, cl)
	<-streams
	exchange(t, a, []byte("reset subject"))
	exchange(t, b, []byte("surviving sibling"))
	writes := h3BlockedWriters(t, a, 1)
	start := time.Now()
	reset.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	reset.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	h3CheckWriters(t, writes, start)
	h3AwaitTerminal(t, sa)
	h3AssertLeases(t, sa.download, 1)
	exchange(t, b, []byte("remote stream reset did not close connection"))
	c, _ := h3DialSession(t, cl)
	<-streams
	exchange(t, c, []byte("same healthy QUIC connection reused after reset"))
	if sockets.Load() != 1 {
		t.Fatal("request reset destroyed healthy pooling", sockets.Load())
	}
}

type h3CloseTracePacket struct {
	net.PacketConn
	phase      atomic.Int32
	writes     atomic.Int32
	closes     atomic.Int32
	wrongOrder atomic.Bool
}

func (p *h3CloseTracePacket) WriteTo(b []byte, a net.Addr) (int, error) {
	if p.phase.Load() == 1 {
		p.writes.Add(1)
	}
	return p.PacketConn.WriteTo(b, a)
}

func (p *h3CloseTracePacket) Close() error {
	p.closes.Add(1)
	if p.phase.Load() != 2 {
		p.wrongOrder.Store(true)
	}
	_ = p.PacketConn.Close()
	return errors.New("injected final UDP Close error")
}

func TestXHTTPH3ShutdownPeerAndOrder(t *testing.T) {
	st, ct := tlsPair(t)
	st.NextProtos = []string{"h3"}
	ct.NextProtos = []string{"h3"}
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &h3CloseTracePacket{PacketConn: raw}
	ln, err := NewPacketListener(p, cfg.Config{Kind: "xhttp"}, st)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	l := ln.(*Listener)
	defer l.Close()
	original := l.carrierClose
	l.carrierClose = func() { p.phase.Store(1); original(); p.phase.Store(2) }
	cp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	tr := &quic.Transport{Conn: cp}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q, err := tr.Dial(ctx, l.Addr(), ct, h3QUICConfig(false, -1))
	if err != nil {
		t.Fatal(err)
	}
	defer q.CloseWithError(0, "test")
	cc := (&http3.Transport{}).NewClientConn(q)
	r, _ := http.NewRequestWithContext(ctx, "OPTIONS", "https://test/", nil)
	resp, err := cc.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	start := time.Now()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if e := l.Close(); e != nil {
				t.Error("existing listener Close policy changed", e)
			}
		})
	}
	wg.Wait()
	select {
	case <-q.Context().Done():
		var app *quic.ApplicationError
		if !errors.As(context.Cause(q.Context()), &app) || !app.Remote {
			t.Fatal("peer did not observe remote QUIC application close", context.Cause(q.Context()))
		}
		t.Log("peer close", app, "elapsed", time.Since(start))
	case <-time.After(time.Second):
		t.Fatal("server Close returned without notifying QUIC peer")
	}
	if p.wrongOrder.Load() || p.closes.Load() != 1 || p.writes.Load() == 0 {
		t.Fatal("H3/QUIC did not write close before exactly one UDP final close", p.wrongOrder.Load(), p.closes.Load(), p.writes.Load())
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed listener accepted", err)
	}
	h3ReclaimClosedPacket(t, raw)
	t.Log("trace: H3/QUIC close begin -> protocol writes", p.writes.Load(), "-> H3/QUIC completion -> UDP Close; concurrent Close callers=8")
}

func TestXHTTPH3ShutdownDuringHandshake(t *testing.T) {
	st, ct := tlsPair(t)
	st.NextProtos = []string{"h3"}
	ct.NextProtos = []string{"h3"}
	entered := make(chan struct{})
	exited := make(chan struct{})
	shutdown := make(chan struct{})
	cert := st.Certificates[0]
	st.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		close(entered)
		defer close(exited)
		<-shutdown
		return &cert, nil
	}
	// Force GetCertificate even though the fixture contains a static certificate.
	st.Certificates = nil
	p, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewPacketListener(p, cfg.Config{Kind: "xhttp"}, st)
	if err != nil {
		p.Close()
		t.Fatal(err)
	}
	defer l.Close()
	listener := l.(*Listener)
	original := listener.carrierClose
	listener.carrierClose = func() { close(shutdown); original() }
	cp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	tr := &quic.Transport{Conn: cp}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		q, e := tr.Dial(ctx, l.Addr(), ct, h3QUICConfig(false, -1))
		if e == nil {
			select {
			case <-q.Context().Done():
				e = context.Cause(q.Context())
			case <-ctx.Done():
				e = ctx.Err()
			}
		}
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handshake did not enter certificate callback")
	}
	l.Close()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("shutdown retained handshake callback")
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("shutdown admitted handshake")
		}
		t.Log("peer handshake shutdown error", e)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not notify handshaking peer")
	}
	h3ReclaimClosedPacket(t, p)
}

func TestXHTTPH3ShutdownOtherModesAndReassembly(t *testing.T) {
	for _, mode := range []string{"stream-up", "packet-up"} {
		t.Run(mode, func(t *testing.T) {
			cl, l, _ := h3Fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: mode}})
			c, s := h3DialSession(t, cl)
			exchange(t, c, []byte("active split upload download"))
			if mode == "packet-up" {
				r, _ := http.NewRequestWithContext(s.ctx, "POST", cl.URL().String(), bytes.NewReader([]byte("queued")))
				if e := decorate(r, cl.config, s.id, "2", false, bytes.NewReader(bytes.Repeat([]byte{1}, 4096))); e != nil {
					t.Fatal(e)
				}
				resp, e := s.upload.request(r)
				if e != nil {
					t.Fatal(e)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				l.mu.Lock()
				pending := l.pending
				l.mu.Unlock()
				if pending != 6 {
					t.Fatal("missing real out-of-order buffered packet", pending)
				}
			}
			c.SetDeadline(time.Time{})
			done := make(chan error, 1)
			go func() { _, e := c.Read(make([]byte, 1)); done <- e }()
			l.Close()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("shutdown read succeeded")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("split leg did not terminate")
			}
			h3AwaitTerminal(t, s)
			h3AssertLeases(t, s.download, 0)
			l.mu.Lock()
			defer l.mu.Unlock()
			if len(l.sessions) != 0 || l.pending != 0 || l.receiving != 0 {
				t.Fatal("orphan split legs or reorder buffers")
			}
		})
	}
}
