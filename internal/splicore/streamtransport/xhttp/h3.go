//go:build with_quic

package xhttp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const h3Compiled = true

// HTTP/3 owns its control/QPACK streams. These limits are independent of the
// Phase31 generic QUIC carrier and of XHTTP's packet reassembly budgets.
func h3QUICConfig(server bool, keep int64) *quic.Config {
	incoming, idle := int64(-1), 300*time.Second
	if server {
		incoming, idle = 128, 30*time.Second
	}
	if keep == 0 && !server {
		keep = 10
	}
	return &quic.Config{
		Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: 5 * time.Second,
		// Fit the IPv6 minimum MTU including UDP/IP headers before PMTU probes.
		InitialPacketSize: 1200,
		MaxIdleTimeout:    idle, KeepAlivePeriod: time.Duration(max(keep, 0)) * time.Second,
		MaxIncomingStreams: incoming, MaxIncomingUniStreams: 16,
		InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 1 << 20,
		InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 8 << 20,
		EnableDatagrams: false, Allow0RTT: false,
	}
}

func h3TLS(tc *tls.Config) *tls.Config {
	tc = tc.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.NextProtos = []string{http3.NextProtoH3}
	// QUIC resumption and VLESS Encryption resumption are separate layers.
	tc.SessionTicketsDisabled = true
	tc.ClientSessionCache = nil
	return tc
}

// PacketSocket transfers a dedicated socket on every dial. Each h3Socket owns
// its QUIC transport and UDP socket; closing it never closes a sibling carrier.
type h3Socket struct {
	packet net.PacketConn
	quic   *quic.Transport
	conn   *quic.Conn
	owner  *h3Carrier
	once   sync.Once
}

func (s *h3Socket) close() {
	s.once.Do(func() { _ = s.quic.Close(); _ = s.packet.Close() })
}

type h3Transport struct {
	*http3.Transport
	socket   PacketSocket
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	sockets  map[*h3Socket]bool
	carriers map[*h3Carrier]bool
	cached   *h3Carrier
	dials    sync.WaitGroup
	once     sync.Once
}

func (h *h3Transport) failed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	// An XMUX entry owns a reusable HTTP/3 Transport, not one QUIC connection.
	// Carrier leases and the origin cache own physical lifetimes. Neither dial
	// completion nor a physical close can retire this whole reusable wrapper
	// (and its other healthy carriers).
	return h.closed
}

// Each GotConn selection allocates a request-attempt token, even if it selects
// the same physical connection. Tentative attempts have no terminal authority:
// the library owns retries until RoundTrip returns a successful response.
type h3Attempt struct{ ctx context.Context }

type h3RequestWatch struct {
	mu                    sync.Mutex
	attempt               *h3Attempt
	active, closed        bool
	stopConn, stopRequest func() bool
	writeErr              error
	fail                  func(error)
}

func (w *h3RequestWatch) selectAttempt(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed && !w.active {
		w.attempt = &h3Attempt{ctx: ctx}
	}
}

func (w *h3RequestWatch) commit() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.attempt == nil || w.attempt.ctx == nil {
		return net.ErrClosed
	}
	a := w.attempt
	if err := context.Cause(a.ctx); err != nil {
		return err
	}
	// Commit and callback registration are serialized with close. A context
	// already canceled (or canceled during registration) still runs the callback.
	w.active = true
	w.stopConn = context.AfterFunc(a.ctx, func() {
		w.mu.Lock()
		authoritative := !w.closed && w.active && w.attempt == a
		w.mu.Unlock()
		// An active watch never changes attempts. Close may revoke it after
		// this decision, but cannot install a different carrier. Run session
		// cancellation and pipe closes outside the ownership mutex.
		if authoritative {
			w.fail(context.Cause(a.ctx))
		}
	})
	if w.writeErr != nil {
		return w.writeErr
	}
	return nil
}

func (w *h3RequestWatch) wroteRequest(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	authoritative := false
	if !w.closed {
		w.writeErr = err
		authoritative = w.active
	}
	w.mu.Unlock()
	if authoritative {
		w.fail(err)
	}
}

func (w *h3RequestWatch) close() {
	w.mu.Lock()
	w.closed = true
	stopConn, stopRequest := w.stopConn, w.stopRequest
	w.stopConn, w.stopRequest, w.attempt = nil, nil, nil
	w.mu.Unlock()
	if stopConn != nil {
		stopConn()
	}
	if stopRequest != nil {
		stopRequest()
	}
}

type h3ResponseBody struct {
	io.ReadCloser
	watch *h3RequestWatch
	fail  func(error)
}

func (b *h3ResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		b.fail(err)
	}
	return n, err
}

func (b *h3ResponseBody) Close() error {
	b.watch.close()
	return b.ReadCloser.Close()
}

func (h *h3Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	fail, ok := r.Context().Value(sessionFailureKey{}).(func(error))
	if !ok {
		return h.roundTrip(r, nil)
	}
	terminal := func(err error) { fail(fmt.Errorf("XHTTP HTTP/3: %w", err)) }
	watch := &h3RequestWatch{fail: terminal}
	watch.mu.Lock()
	watch.stopRequest = context.AfterFunc(r.Context(), watch.close)
	watch.mu.Unlock()
	trace := &httptrace.ClientTrace{}
	// Streaming bodies cannot be replayed after sending. Their asynchronous
	// sender must release a backpressured response on failure. Replayable bodies
	// instead use the library's final RoundTrip/body result: WroteRequest has no
	// attempt identity and a superseded sender can report after a retry succeeds.
	if r.Body != nil && r.Body != http.NoBody && r.GetBody == nil {
		trace.WroteRequest = func(info httptrace.WroteRequestInfo) { watch.wroteRequest(info.Err) }
	}
	resp, err := h.roundTrip(r.WithContext(httptrace.WithClientTrace(r.Context(), trace)), watch)
	if err == nil && resp.StatusCode == http.StatusOK {
		err = watch.commit()
		if err != nil {
			_ = resp.Body.Close()
		}
	}
	if err != nil {
		watch.close()
		terminal(err)
		return nil, err
	}
	resp.Body = &h3ResponseBody{ReadCloser: resp.Body, watch: watch, fail: terminal}
	return resp, nil
}

func newH3Transport(s Security, keep int64) http.RoundTripper {
	ctx, cancel := context.WithCancel(context.Background())
	h := &h3Transport{socket: s.PacketSocket, ctx: ctx, cancel: cancel, sockets: map[*h3Socket]bool{}, carriers: map[*h3Carrier]bool{}}
	h.Transport = &http3.Transport{
		TLSClientConfig: h3TLS(s.TLS), QUICConfig: h3QUICConfig(false, keep),
		MaxResponseHeaderBytes: 1 << 20, DisableCompression: true, Dial: h.dial,
	}
	return h
}

func (h *h3Transport) dial(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
	return h.dialOwned(ctx, "", tc, qc, nil)
}

func (h *h3Transport) dialOwned(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config, owner *h3Carrier) (*quic.Conn, error) {
	h.mu.Lock()
	if h.closed || (owner != nil && owner.retiring) {
		h.mu.Unlock()
		return nil, net.ErrClosed
	}
	h.dials.Add(1)
	h.mu.Unlock()
	defer h.dials.Done()
	admission, cancel := context.WithTimeout(ctx, cfg.XHTTPLegAdmissionTimeout)
	defer cancel()
	stop := context.AfterFunc(h.ctx, cancel)
	defer stop()
	p, peer, err := h.socket(admission)
	if err != nil {
		if p != nil {
			_ = p.Close()
		}
		return nil, err
	}
	// Never pass a hostname to quic-go. Resolution belongs to Core DNS/underlay.
	addr, ok := peer.(*net.UDPAddr)
	if p == nil || !ok || addr.IP.To16() == nil || addr.Port <= 0 || addr.Port > 65535 {
		if p != nil {
			_ = p.Close()
		}
		return nil, errEnvelope
	}
	socket := &h3Socket{packet: p, quic: &quic.Transport{Conn: p}, owner: owner}
	h.mu.Lock()
	if h.closed || (owner != nil && owner.retiring) {
		h.mu.Unlock()
		socket.close()
		return nil, net.ErrClosed
	}
	h.sockets[socket] = true
	if owner != nil {
		owner.socket = socket
	}
	h.mu.Unlock()
	release := func() {
		socket.close()
		h.mu.Lock()
		delete(h.sockets, socket)
		if owner != nil && h.cached == owner {
			h.cached = nil
		}
		retire := owner != nil && owner.refs == 0 && !owner.retiring
		if retire {
			owner.retiring = true
		}
		h.mu.Unlock()
		if retire {
			// This release can run inside the inner Transport's Dial callback.
			// Transport.Close waits for that callback, so finish retirement off
			// the dialing goroutine. The owned socket is already closed above.
			go owner.close()
		}
	}
	q, err := socket.quic.Dial(admission, addr, tc, qc)
	if err != nil {
		release()
		return nil, err
	}
	h.mu.Lock()
	closed := h.closed || (owner != nil && owner.retiring)
	if !closed {
		socket.conn = q
	}
	h.mu.Unlock()
	if q.ConnectionState().TLS.NegotiatedProtocol != http3.NextProtoH3 || closed {
		_ = q.CloseWithError(0, "closed")
		release()
		return nil, errEnvelope
	}
	context.AfterFunc(q.Context(), release)
	return q, nil
}

func (h *h3Transport) Close() error {
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.cached = nil
		carriers := make([]*h3Carrier, 0, len(h.carriers))
		for c := range h.carriers {
			c.retiring = true
			carriers = append(carriers, c)
		}
		sockets := make([]*h3Socket, 0, len(h.sockets))
		for s := range h.sockets {
			sockets = append(sockets, s)
		}
		h.mu.Unlock()
		h.cancel()
		for _, c := range carriers {
			c.close()
		}
		_ = h.Transport.Close()
		for _, s := range sockets {
			s.close()
		}
		h.dials.Wait()
		h.mu.Lock()
		clear(h.sockets)
		clear(h.carriers)
		h.mu.Unlock()
	})
	return nil
}

// packetListener supplies the address/ownership seam of the existing listener;
// its Accept is never used. HTTP/3 feeds the shared ServeHTTP/session layer.
type packetListener struct{ net.PacketConn }

func (*packetListener) Accept() (net.Conn, error) { return nil, errEnvelope }
func (p *packetListener) Addr() net.Addr          { return p.LocalAddr() }

func NewPacketListener(p net.PacketConn, c cfg.Config, tc *tls.Config) (net.Listener, error) {
	if p == nil || tc == nil || !c.XHTTPH3(tc.NextProtos) || c.ValidateServer() != nil || tc.MaxVersion != 0 && tc.MaxVersion < tls.VersionTLS13 || len(tc.Certificates) == 0 && tc.GetCertificate == nil {
		return nil, errEnvelope
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		base: &packetListener{p}, config: c.Clone(), ctx: ctx, cancel: cancel,
		server: &http.Server{}, sessions: map[string]*session{}, connections: map[net.Conn]bool{},
		queue: make(chan net.Conn, 64), entropy: rand.Reader,
	}
	slots := make(chan struct{}, 128)
	tr := &quic.Transport{
		Conn: p, VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			select {
			case slots <- struct{}{}:
				context.AfterFunc(ctx, func() { <-slots })
				return ctx, nil
			default:
				return nil, errEnvelope
			}
		},
	}
	ql, err := tr.Listen(h3TLS(tc), h3QUICConfig(true, 0))
	if err != nil {
		cancel()
		_ = tr.Close()
		return nil, err
	}
	server := &http3.Server{Handler: l, MaxHeaderBytes: int(options(c).HeaderBytes), IdleTimeout: 60 * time.Second}
	l.carrierClose = func() { _ = server.Close(); _ = ql.Close(); _ = tr.Close() }
	l.workers.Go(func() {
		defer cancel()
		_ = server.ServeListener(ql)
	})
	return l, nil
}
