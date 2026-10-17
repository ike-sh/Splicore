package xhttp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"golang.org/x/net/http2"
)

const sessionLimit = 512
const sessionBytes = 32 << 20
const totalBytes = 128 << 20
const associationTimeout = cfg.XHTTPAdmissionTimeout

type Handshake func(context.Context, net.Conn) (net.Conn, error)
type logicalConn struct {
	net.Conn
	close          func()
	local, remote  net.Addr
	admissionChunk int
	admissionStart func()
}

func (c *logicalConn) Close() error         { c.close(); return nil }
func (c *logicalConn) LocalAddr() net.Addr  { return c.local }
func (c *logicalConn) RemoteAddr() net.Addr { return c.remote }

type firstDataConn struct {
	net.Conn
	mu    sync.Mutex
	first []byte
	ready func()
}

func (c *firstDataConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.first) > 0 {
		if c.ready != nil {
			c.ready()
			c.ready = nil
		}
		n := copy(b, c.first)
		c.first = c.first[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

type address string

func (address) Network() string  { return "xhttp" }
func (a address) String() string { return string(a) }

type Listener struct {
	base        net.Listener
	config      cfg.Config
	ctx         context.Context
	cancel      context.CancelFunc
	server      *http.Server
	mu          sync.Mutex
	closed      bool
	sessions    map[string]*session
	connections map[net.Conn]bool
	queue       chan net.Conn
	pending     int
	receiving   int
	workers     sync.WaitGroup
	once        sync.Once
	entropy     io.Reader
}
type session struct {
	owner                 *Listener
	id                    string
	ctx                   context.Context
	cancel                context.CancelFunc
	app, bridge           net.Conn
	mu                    sync.Mutex
	packets               map[uint64][]byte
	bytes                 int
	next                  uint64
	kind                  string
	associated, uploading bool
	notify                chan struct{}
	timer                 *time.Timer
	once                  sync.Once
}

func NewListener(base net.Listener, c cfg.Config, tc *tls.Config, handshake Handshake) (net.Listener, error) {
	if base == nil || c.Type() != "xhttp" || c.ValidateServer() != nil {
		return nil, errEnvelope
	}
	if tc != nil && c.ValidateALPN(tc.NextProtos) != nil {
		return nil, errEnvelope
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{base: base, config: c.Clone(), ctx: ctx, cancel: cancel, sessions: map[string]*session{}, connections: map[net.Conn]bool{}, queue: make(chan net.Conn, 64), entropy: rand.Reader}
	x := options(c)
	l.server = &http.Server{Handler: l, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: int(x.HeaderBytes)}
	h2 := &http2.Server{MaxConcurrentStreams: 128, MaxReadFrameSize: 1 << 20, IdleTimeout: 60 * time.Second}
	if e := http2.ConfigureServer(l.server, h2); e != nil {
		cancel()
		return nil, e
	}
	l.workers.Add(1)
	go func() {
		defer l.workers.Done()
		if handshake != nil {
			for {
				c, e := l.acceptSocket()
				if e != nil {
					return
				}
				l.mu.Lock()
				if l.closed {
					l.mu.Unlock()
					c.Close()
					return
				}
				l.workers.Add(1)
				l.mu.Unlock()
				go func() {
					defer l.workers.Done()
					defer c.Close()
					admission, stop := context.WithTimeout(l.ctx, 5*time.Second)
					defer stop()
					secure, e := handshake(admission, c)
					if e != nil {
						return
					}
					defer secure.Close()
					_ = secure.SetDeadline(time.Time{})
					h2.ServeConn(secure, &http2.ServeConnOpts{Context: l.ctx, BaseConfig: l.server, Handler: l})
				}()
			}
		}
		var serving net.Listener = &socketListener{Listener: base, owner: l}
		if tc != nil {
			t := tc.Clone()
			if len(t.NextProtos) == 0 {
				t.NextProtos = []string{"h2", "http/1.1"}
			}
			serving = tls.NewListener(serving, t)
		}
		_ = l.server.Serve(serving)
	}()
	return l, nil
}

type socketListener struct {
	net.Listener
	owner *Listener
}

func (s *socketListener) Accept() (net.Conn, error) { return s.owner.acceptSocket() }

type socket struct {
	net.Conn
	owner *Listener
	once  sync.Once
}

func (s *socket) Close() error {
	e := s.Conn.Close()
	s.once.Do(func() { s.owner.mu.Lock(); delete(s.owner.connections, s); s.owner.mu.Unlock() })
	return e
}
func (l *Listener) acceptSocket() (net.Conn, error) {
	for {
		raw, e := l.base.Accept()
		if e != nil {
			return nil, e
		}
		l.mu.Lock()
		if l.closed || len(l.connections) >= 512 {
			closed := l.closed
			l.mu.Unlock()
			raw.Close()
			if closed {
				return nil, net.ErrClosed
			}
			continue
		}
		c := &socket{Conn: raw, owner: l}
		l.connections[c] = true
		l.mu.Unlock()
		return c, nil
	}
}
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	case c := <-l.queue:
		if l.ctx.Err() != nil {
			c.Close()
			return nil, net.ErrClosed
		}
		return c, nil
	}
}
func (l *Listener) Addr() net.Addr { return l.base.Addr() }
func (l *Listener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.closed = true
		sessions := make([]*session, 0, len(l.sessions))
		for _, s := range l.sessions {
			sessions = append(sessions, s)
		}
		sockets := make([]net.Conn, 0, len(l.connections))
		for s := range l.connections {
			sockets = append(sockets, s)
		}
		l.mu.Unlock()
		l.cancel()
		l.base.Close()
		for _, s := range sessions {
			s.close()
		}
		l.server.Close()
		for _, s := range sockets {
			s.Close()
		}
		l.workers.Wait()
	})
	return nil
}
func (l *Listener) allocate(id string) (*session, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.allocateLocked(id)
}
func (l *Listener) allocateGenerated() (*session, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, net.ErrClosed
	}
	for attempt := 0; attempt < sessionIDAttempts; attempt++ {
		id, err := sessionToken(cfg.XHTTP{}, l.entropy)
		if err != nil {
			return nil, err
		}
		if l.sessions[id] != nil {
			continue
		}
		return l.allocateLocked(id)
	}
	return nil, errors.New("XHTTP session identity collision bound")
}
func (l *Listener) allocateLocked(id string) (*session, error) {
	if l.closed {
		return nil, net.ErrClosed
	}
	if s := l.sessions[id]; s != nil {
		return s, nil
	}
	if len(l.sessions) >= sessionLimit {
		return nil, errors.New("XHTTP session bound")
	}
	ctx, cancel := context.WithCancel(l.ctx)
	a, b := net.Pipe()
	s := &session{owner: l, id: id, ctx: ctx, cancel: cancel, app: a, bridge: b, packets: map[uint64][]byte{}, notify: make(chan struct{}, 1)}
	l.sessions[id] = s
	s.timer = time.AfterFunc(associationTimeout, s.close)
	l.workers.Add(1)
	go s.deliver()
	return s, nil
}
func (s *session) close() {
	s.once.Do(func() {
		s.cancel()
		s.app.Close()
		s.bridge.Close()
		s.mu.Lock()
		if s.timer != nil {
			s.timer.Stop()
		}
		n := 0
		for _, b := range s.packets {
			n += len(b)
		}
		s.packets = map[uint64][]byte{}
		s.bytes -= n
		s.mu.Unlock()
		s.owner.mu.Lock()
		s.owner.pending -= n
		if s.owner.sessions[s.id] == s {
			delete(s.owner.sessions, s.id)
		}
		s.owner.mu.Unlock()
	})
}
func (s *session) enqueue(seq uint64, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := options(s.owner.config)
	if s.ctx.Err() != nil || s.kind != "" && s.kind != "packet-up" || seq < s.next || seq-s.next > uint64(x.Buffered) || len(s.packets) >= int(x.Buffered) || s.bytes+len(b) > sessionBytes {
		return errEnvelope
	}
	if _, exists := s.packets[seq]; exists {
		return errEnvelope
	}
	s.owner.mu.Lock()
	if s.owner.pending+s.owner.receiving+len(b) > totalBytes {
		s.owner.mu.Unlock()
		return errEnvelope
	}
	s.owner.pending += len(b)
	s.owner.mu.Unlock()
	s.kind = "packet-up"
	s.packets[seq] = b
	s.bytes += len(b)
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return nil
}
func (s *session) deliver() {
	defer s.owner.workers.Done()
	var gapUntil time.Time
	var gapSequence uint64
	for {
		s.mu.Lock()
		b, ok := s.packets[s.next]
		if ok {
			delete(s.packets, s.next)
			s.next++
		}
		gap := len(s.packets) > 0
		next := s.next
		s.mu.Unlock()
		if ok {
			_, e := s.bridge.Write(b)
			s.mu.Lock()
			s.bytes -= len(b)
			s.mu.Unlock()
			s.owner.mu.Lock()
			s.owner.pending -= len(b)
			s.owner.mu.Unlock()
			if e != nil {
				s.close()
				return
			}
			continue
		}
		var deadline <-chan time.Time
		var timer *time.Timer
		if gap {
			if gapUntil.IsZero() || gapSequence != next {
				gapUntil = time.Now().Add(associationTimeout)
				gapSequence = next
			}
			timer = time.NewTimer(time.Until(gapUntil))
			deadline = timer.C
		} else {
			gapUntil = time.Time{}
		}
		select {
		case <-s.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.notify:
			if timer != nil {
				timer.Stop()
			}
		case <-deadline:
			s.close()
			return
		}
	}
}
func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		http.Error(w, "closed", 503)
		return
	}
	l.workers.Add(1)
	l.mu.Unlock()
	defer l.workers.Done()
	if e := responseHeaders(w, r, l.config); e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
		w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
		w.WriteHeader(200)
		return
	}
	sid, seq, e := parseEnvelope(r, l.config)
	if e != nil {
		http.Error(w, "invalid envelope", 400)
		return
	}
	x := options(l.config)
	kind := "stream-down"
	if sid == "" {
		kind = "stream-one"
	} else if seq != "" {
		kind = "packet-up"
	} else if r.Method != "GET" {
		kind = "stream-up"
	}
	if kind == "stream-one" && x.Mode != "auto" && x.Mode != "stream-one" && x.Mode != "stream-up" || kind == "packet-up" && x.Mode != "auto" && x.Mode != "packet-up" || kind == "stream-up" && x.Mode != "auto" && x.Mode != "stream-up" {
		http.Error(w, "mode mismatch", 400)
		return
	}
	if kind == "stream-one" && r.ProtoMajor == 1 {
		http.Error(w, "stream-one requires HTTP/2", 400)
		return
	}
	if (kind == "packet-up" || kind == "stream-up" || kind == "stream-one") && r.Method != x.Method {
		http.Error(w, "method mismatch", 405)
		return
	}
	var s *session
	if kind == "stream-one" {
		s, e = l.allocateGenerated()
	} else {
		s, e = l.allocate(sid)
	}
	if e != nil {
		http.Error(w, "session bound", 503)
		return
	}
	if kind == "packet-up" {
		n, e := strconv.ParseUint(seq, 10, 64)
		if e != nil {
			http.Error(w, "invalid sequence", 400)
			return
		}
		reservation := int(x.PacketBytes.Max)
		l.mu.Lock()
		if l.pending+l.receiving+reservation > totalBytes {
			l.mu.Unlock()
			http.Error(w, "packet memory bound", 503)
			return
		}
		l.receiving += reservation
		l.mu.Unlock()
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(associationTimeout))
		b, e := packetPayload(r, l.config)
		_ = controller.SetReadDeadline(time.Time{})
		l.mu.Lock()
		l.receiving -= reservation
		l.mu.Unlock()
		if e != nil {
			http.Error(w, "invalid packet", 413)
			return
		}
		if e = s.enqueue(n, b); e != nil {
			http.Error(w, "sequence or queue bound", 409)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		return
	}
	if kind == "stream-up" {
		_ = http.NewResponseController(w).EnableFullDuplex()
		s.mu.Lock()
		if s.uploading || s.kind != "" && s.kind != "stream-up" {
			s.mu.Unlock()
			http.Error(w, "duplicate upload", 409)
			return
		}
		s.kind = kind
		s.uploading = true
		s.mu.Unlock()
		defer s.close()
		stop := context.AfterFunc(s.ctx, func() { r.Body.Close() })
		defer stop()
		responseDone := make(chan struct{})
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return
		}
		l.workers.Add(1)
		l.mu.Unlock()
		go func() {
			defer l.workers.Done()
			_, _ = io.CopyBuffer(s.bridge, r.Body, make([]byte, 32<<10))
			close(responseDone)
		}()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(200)
		// Stream-up response padding is transport keepalive, never application data.
		for {
			seconds, e := x.KeepAlive.Pick(rand.Reader)
			if e != nil {
				return
			}
			var tick <-chan time.Time
			var t *time.Timer
			if seconds > 0 {
				p, e := padding(x, rand.Reader)
				if e != nil {
					return
				}
				if _, e = io.WriteString(w, p); e != nil {
					return
				}
				_ = http.NewResponseController(w).Flush()
				t = time.NewTimer(time.Duration(seconds) * time.Second)
				tick = t.C
			} else {
				_ = http.NewResponseController(w).Flush()
			}
			select {
			case <-s.ctx.Done():
				if t != nil {
					t.Stop()
				}
				return
			case <-r.Context().Done():
				if t != nil {
					t.Stop()
				}
				s.close()
				return
			case <-responseDone:
				if t != nil {
					t.Stop()
				}
				return
			case <-tick:
			}
		}
	}
	s.mu.Lock()
	if s.associated {
		s.mu.Unlock()
		http.Error(w, "duplicate download", 409)
		return
	}
	s.associated = true
	s.mu.Unlock()
	defer s.close()
	stop := context.AfterFunc(r.Context(), s.close)
	defer stop()
	if kind == "stream-one" {
		_ = http.NewResponseController(w).EnableFullDuplex()
		stopBody := context.AfterFunc(s.ctx, func() { r.Body.Close() })
		defer stopBody()
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return
		}
		l.workers.Add(1)
		l.mu.Unlock()
		go func() {
			defer l.workers.Done()
			_, _ = io.CopyBuffer(s.bridge, r.Body, make([]byte, 32<<10))
			s.close()
		}()
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	if !x.NoSSE {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.WriteHeader(200)
	_ = http.NewResponseController(w).Flush()
	// HTTP headers unblock the client's startup; native admission must wait
	// until the transport actually has application data. The association timer
	// remains armed through this read and closes both pipe endpoints on expiry.
	first := make([]byte, 1)
	if _, e := io.ReadFull(s.app, first); e != nil {
		return
	}
	if s.ctx.Err() != nil {
		return
	}
	ready := func() { s.mu.Lock(); s.timer.Stop(); s.mu.Unlock() }
	conn := &logicalConn{Conn: &firstDataConn{Conn: s.app, first: first, ready: ready}, close: s.close, local: l.base.Addr(), remote: address(r.RemoteAddr), admissionStart: ready}
	select {
	case l.queue <- conn:
	case <-s.ctx.Done():
		return
	default:
		http.Error(w, "admission bound", 503)
		return
	}
	b := make([]byte, 32<<10)
	for {
		n, e := s.bridge.Read(b)
		if n > 0 {
			if _, e := w.Write(b[:n]); e != nil {
				return
			}
			if e := http.NewResponseController(w).Flush(); e != nil {
				return
			}
		}
		if e != nil {
			return
		}
	}
}
