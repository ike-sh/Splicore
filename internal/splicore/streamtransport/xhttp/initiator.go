package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"golang.org/x/net/http2"
)

type DialFunc func(context.Context, string, string) (net.Conn, error)
type Security struct {
	TLS        *tls.Config
	Handshake  Handshake
	ServerName string
	Reality    bool
}
type Resolver func(cfg.Download) (Security, error)
type Client struct {
	dial       DialFunc
	config     cfg.Config
	security   Security
	target     string
	pool       *connectionPool
	downstream *Client
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	sessions   map[*clientSession]bool
	identities map[string]*clientSession
	entropy    io.Reader
	workers    sync.WaitGroup
	closed     bool
	once       sync.Once
}
type connectionPool struct {
	owner                          *Client
	mu                             sync.Mutex
	entries                        []*httpEntry
	maxConnections, maxConcurrency int
	closed                         bool
}
type httpEntry struct {
	pool                                              *connectionPool
	transport                                         http.RoundTripper
	active, reuse, requests, requestLimit, reuseLimit int
	expires                                           time.Time
	retired                                           bool
	mu                                                sync.Mutex
	sockets                                           map[net.Conn]bool
	closed                                            bool
}
type clientSession struct {
	id               string
	client           *Client
	ctx              context.Context
	cancel           context.CancelFunc
	app, bridge      net.Conn
	upload, download *httpEntry
	once             sync.Once
	workers          sync.WaitGroup
	joined           chan struct{}
	ready            chan error
}

func NewClient(dial DialFunc, target string, c cfg.Config, security Security, resolve Resolver) (*Client, error) {
	if dial == nil || c.Type() != "xhttp" || c.ValidateClient() != nil {
		return nil, errEnvelope
	}
	if security.TLS != nil && c.ValidateALPN(security.TLS.NextProtos) != nil {
		return nil, errEnvelope
	}
	if c.XHTTP != nil {
		mode := c.XHTTP.SelectMode(security.Reality)
		if mode != "packet-up" && (c.XHTTP.Interval != (cfg.Range{}) || c.XHTTP.PacketBytes != (cfg.Range{})) || mode == "packet-up" && c.XHTTP.NoGRPC || mode == "stream-one" && c.XHTTP.SessionTable != "" {
			return nil, errEnvelope
		}
	}
	if options(c).SelectMode(security.Reality) == "stream-one" && httpVersion(security) == 1 {
		return nil, errors.New("XHTTP stream-one requires HTTP/2")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cl := &Client{dial: dial, target: target, config: c.Clone(), security: security, ctx: ctx, cancel: cancel, sessions: map[*clientSession]bool{}, identities: map[string]*clientSession{}, entropy: rand.Reader}
	x := options(c)
	m := x.XMUX
	mc, e := m.MaxConnections.Pick(rand.Reader)
	if e != nil {
		cancel()
		return nil, e
	}
	con, e := m.MaxConcurrency.Pick(rand.Reader)
	if e != nil {
		cancel()
		return nil, e
	}
	cl.pool = &connectionPool{owner: cl, maxConnections: mc, maxConcurrency: con}
	if d := x.Download; d != nil {
		if resolve == nil {
			cancel()
			return nil, errors.New("XHTTP download security resolver required")
		}
		s, e := resolve(*d)
		if e != nil {
			cancel()
			return nil, e
		}
		cl.downstream, e = NewClient(dial, net.JoinHostPort(d.Endpoint.Host, strconv.Itoa(int(d.Endpoint.Port))), d.Transport, s, nil)
		if e != nil {
			cancel()
			return nil, e
		}
	}
	return cl, nil
}
func httpVersion(s Security) int {
	if s.Reality {
		return 2
	}
	if s.TLS == nil && s.Handshake == nil {
		return 1
	}
	if s.TLS != nil && len(s.TLS.NextProtos) == 1 && s.TLS.NextProtos[0] == "http/1.1" {
		return 1
	}
	return 2
}
func (c *Client) URL() *url.URL {
	scheme := "http"
	if c.security.TLS != nil || c.security.Handshake != nil {
		scheme = "https"
	}
	host := c.config.Host
	if host == "" {
		host = c.security.ServerName
	}
	if host == "" && c.security.TLS != nil {
		host = c.security.TLS.ServerName
	}
	if host == "" {
		host, _, _ = net.SplitHostPort(c.target)
	}
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	path, query := c.config.XHTTPPath()
	return &url.URL{Scheme: scheme, Host: host, Path: path, RawQuery: query}
}
func (p *connectionPool) lease() (*httpEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	current := p.entries[:0]
	var best *httpEntry
	for _, e := range p.entries {
		if !e.expires.IsZero() && time.Now().After(e.expires) || e.reuseLimit > 0 && e.reuse >= e.reuseLimit || e.requestLimit > 0 && e.requests >= e.requestLimit {
			e.retired = true
		}
		if e.retired && e.active == 0 {
			e.close()
			continue
		}
		current = append(current, e)
		if !e.retired && (p.maxConcurrency == 0 || e.active < p.maxConcurrency) && (best == nil || e.active < best.active) {
			best = e
		}
	}
	p.entries = current
	if best == nil || p.maxConnections > 0 && len(current) < p.maxConnections {
		if len(current) >= 128 {
			return nil, errors.New("XHTTP HTTP pool bound")
		}
		var err error
		best, err = p.newEntry()
		if err != nil {
			return nil, err
		}
		p.entries = append(p.entries, best)
	}
	best.active++
	best.reuse++
	return best, nil
}
func (p *connectionPool) release(e *httpEntry) {
	p.mu.Lock()
	e.active--
	if e.retired && e.active == 0 {
		e.close()
	}
	p.mu.Unlock()
}
func (p *connectionPool) close() {
	p.mu.Lock()
	p.closed = true
	for _, e := range p.entries {
		e.close()
	}
	p.entries = nil
	p.mu.Unlock()
}
func (p *connectionPool) newEntry() (*httpEntry, error) {
	m := options(p.owner.config).XMUX
	r, e := m.Reuse.Pick(rand.Reader)
	if e != nil {
		return nil, e
	}
	n, e := m.Requests.Pick(rand.Reader)
	if e != nil {
		return nil, e
	}
	life, e := m.Lifetime.Pick(rand.Reader)
	if e != nil {
		return nil, e
	}
	entry := &httpEntry{pool: p, reuseLimit: r, requestLimit: n, sockets: map[net.Conn]bool{}}
	if life > 0 {
		entry.expires = time.Now().Add(time.Duration(life) * time.Second)
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) { return entry.connect(ctx, false) }
	secured := func(ctx context.Context, _, _ string) (net.Conn, error) { return entry.connect(ctx, true) }
	if httpVersion(p.owner.security) == 2 {
		keep := time.Duration(m.KeepAlive) * time.Second
		if keep == 0 {
			keep = 45 * time.Second
		}
		if keep < 0 {
			keep = 0
		}
		entry.transport = &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) { return secured(ctx, n, a) }, ReadIdleTimeout: keep, PingTimeout: 15 * time.Second, MaxHeaderListSize: 1 << 20}
	} else {
		// Each H1 downstream holds a socket until its logical session closes.
		// Reserve capacity for uploads across the client's bounded 512 sessions.
		entry.transport = &http.Transport{Proxy: nil, DialContext: dial, DialTLSContext: secured, MaxConnsPerHost: 1024, MaxIdleConnsPerHost: 2, IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: cfg.XHTTPLegAdmissionTimeout, MaxResponseHeaderBytes: 1 << 20, DisableCompression: true}
	}
	return entry, nil
}

type ownedSocket struct {
	net.Conn
	entry *httpEntry
	once  sync.Once
}

func (c *ownedSocket) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.entry.mu.Lock(); delete(c.entry.sockets, c); c.entry.mu.Unlock() })
	return e
}
func (e *httpEntry) connect(ctx context.Context, secured bool) (net.Conn, error) {
	admission, stop := context.WithTimeout(ctx, cfg.XHTTPLegAdmissionTimeout)
	defer stop()
	raw, err := e.pool.owner.dial(admission, "tcp", e.pool.owner.target)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		raw.Close()
		return nil, net.ErrClosed
	}
	tracked := &ownedSocket{Conn: raw, entry: e}
	e.sockets[tracked] = true
	e.mu.Unlock()
	done := make(chan struct{})
	abort := context.AfterFunc(admission, func() { defer close(done); tracked.Close() })
	defer func() {
		if !abort() {
			<-done
		}
	}()
	ok := false
	defer func() {
		if !ok {
			tracked.Close()
		}
	}()
	s := e.pool.owner.security
	var c net.Conn = tracked
	if secured && (s.Handshake != nil || s.TLS != nil) {
		if s.Handshake != nil {
			c, err = s.Handshake(admission, tracked)
		} else {
			tc := s.TLS.Clone()
			if httpVersion(s) == 2 {
				tc.NextProtos = []string{"h2"}
			} else {
				tc.NextProtos = []string{"http/1.1"}
			}
			t := tls.Client(tracked, tc)
			err = t.HandshakeContext(admission)
			c = t
			if err == nil && httpVersion(s) == 2 && t.ConnectionState().NegotiatedProtocol != "h2" {
				err = errors.New("XHTTP peer did not negotiate HTTP/2")
			}
		}
		if err != nil {
			return nil, err
		}
		_ = c.SetDeadline(time.Time{})
	}
	if admission.Err() != nil {
		return nil, admission.Err()
	}
	ok = true
	return c, nil
}
func (e *httpEntry) close() {
	if v, ok := e.transport.(interface{ CloseIdleConnections() }); ok {
		v.CloseIdleConnections()
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	sockets := make([]net.Conn, 0, len(e.sockets))
	for s := range e.sockets {
		sockets = append(sockets, s)
	}
	e.mu.Unlock()
	for _, s := range sockets {
		s.Close()
	}
}
func (e *httpEntry) request(r *http.Request) (*http.Response, error) {
	e.pool.mu.Lock()
	e.requests++
	if e.requestLimit > 0 && e.requests >= e.requestLimit {
		e.retired = true
	}
	e.pool.mu.Unlock()
	resp, err := e.transport.RoundTrip(r)
	if err == nil && resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, errors.New("XHTTP peer rejected request")
	}
	return resp, err
}
func (s *clientSession) close() { s.once.Do(func() { s.cancel(); s.app.Close(); s.bridge.Close() }) }
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	upload, e := c.pool.lease()
	if e != nil {
		return nil, e
	}
	downClient := c
	if c.downstream != nil {
		downClient = c.downstream
	}
	download := upload
	if downClient != c {
		download, e = downClient.pool.lease()
		if e != nil {
			c.pool.release(upload)
			return nil, e
		}
	}
	life, cancel := context.WithCancel(c.ctx)
	a, b := net.Pipe()
	s := &clientSession{client: c, ctx: life, cancel: cancel, app: a, bridge: b, upload: upload, download: download, joined: make(chan struct{}), ready: make(chan error, 1)}
	mode := options(c.config).SelectMode(c.security.Reality)
	e = c.reserveSession(s, mode)
	if e != nil {
		s.close()
		c.pool.release(upload)
		if download != upload {
			downClient.pool.release(download)
		}
		return nil, e
	}
	sid := s.id
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		if e != nil {
			s.ready <- e
			return
		}
		s.run(mode, sid, downClient)
	}()
	go func() {
		defer c.workers.Done()
		s.workers.Wait()
		s.close()
		s.upload.pool.release(s.upload)
		if s.download != s.upload {
			s.download.pool.release(s.download)
		}
		c.mu.Lock()
		delete(c.sessions, s)
		if s.id != "" && c.identities[s.id] == s {
			delete(c.identities, s.id)
		}
		c.mu.Unlock()
		close(s.joined)
	}()
	timer := time.NewTimer(cfg.XHTTPLegAdmissionTimeout)
	defer timer.Stop()
	select {
	case e := <-s.ready:
		if e != nil {
			s.close()
			<-s.joined
			return nil, e
		}
	case <-ctx.Done():
		s.close()
		<-s.joined
		return nil, ctx.Err()
	case <-timer.C:
		s.close()
		<-s.joined
		return nil, errors.New("XHTTP admission timeout")
	}
	if ctx.Err() != nil {
		s.close()
		return nil, ctx.Err()
	}
	x := options(c.config)
	chunk := min(int(x.PacketBytes.Min), admissionBytes)
	if x.DataPlacement == "header" || x.DataPlacement == "cookie" {
		chunk = min(chunk, int(x.HeaderBytes)/2)
	}
	return &logicalConn{Conn: s.app, close: s.close, local: address("xhttp-client"), remote: address(c.target), admissionChunk: chunk}, nil
}

const sessionIDAttempts = 8

// Reserve before starting HTTP legs, retaining the ID until all workers exit.
// The mutex also serializes the secure entropy reader and concurrent insertion.
func (c *Client) reserveSession(s *clientSession, mode string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.sessions) >= 512 {
		return net.ErrClosed
	}
	if mode != "stream-one" {
		for attempt := 0; attempt < sessionIDAttempts; attempt++ {
			id, err := sessionToken(options(c.config), c.entropy)
			if err != nil {
				return err
			}
			if c.identities[id] != nil {
				continue
			}
			s.id = id
			c.identities[id] = s
			break
		}
		if s.id == "" {
			return errors.New("XHTTP session identity collision bound")
		}
	}
	c.sessions[s] = true
	c.workers.Add(1)
	return nil
}
func (s *clientSession) run(mode, sid string, down *Client) {
	defer s.close()
	if mode == "packet-up" {
		s.workers.Add(1)
		go func() { defer s.workers.Done(); s.packets(sid) }()
	} else {
		pr, pw := io.Pipe()
		stop := context.AfterFunc(s.ctx, func() { pr.Close(); pw.Close() })
		defer stop()
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			defer pw.Close()
			_, _ = io.CopyBuffer(pw, s.bridge, make([]byte, 32<<10))
		}()
		r, _ := http.NewRequestWithContext(s.ctx, options(s.client.config).Method, s.client.URL().String(), pr)
		if e := decorate(r, s.client.config, sid, "", true, rand.Reader); e != nil {
			s.ready <- e
			return
		}
		if mode == "stream-one" {
			resp, e := s.upload.request(r)
			s.ready <- e
			if e != nil {
				return
			}
			defer resp.Body.Close()
			_, _ = io.CopyBuffer(s.bridge, resp.Body, make([]byte, 32<<10))
			return
		}
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			defer s.close()
			resp, e := s.upload.request(r)
			if e != nil {
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}()
	}
	r, _ := http.NewRequestWithContext(s.ctx, "GET", down.URL().String(), nil)
	if e := decorate(r, down.config, sid, "", false, rand.Reader); e != nil {
		s.ready <- e
		return
	}
	resp, e := s.download.request(r)
	s.ready <- e
	if e != nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.CopyBuffer(s.bridge, resp.Body, make([]byte, 32<<10))
}
func (s *clientSession) packets(sid string) {
	defer s.close()
	x := options(s.client.config)
	seq := uint64(0)
	var lastRequest time.Time
	for {
		maxBytes, e := x.PacketBytes.Pick(rand.Reader)
		if e != nil {
			return
		}
		if x.DataPlacement == "header" || x.DataPlacement == "cookie" {
			maxBytes = min(maxBytes, int(x.HeaderBytes)/2)
		}
		b := make([]byte, maxBytes)
		n, e := s.bridge.Read(b)
		if e != nil {
			return
		}
		interval, e := x.Interval.Pick(rand.Reader)
		if e != nil {
			return
		}
		if x.Interval.Min <= 0 {
			interval = 0
		}
		if interval > 0 {
			_ = s.bridge.SetReadDeadline(time.Now().Add(time.Duration(interval) * time.Millisecond))
			for n < len(b) {
				v, e := s.bridge.Read(b[n:])
				n += v
				if e != nil {
					break
				}
			}
			_ = s.bridge.SetReadDeadline(time.Time{})
		}
		s.upload.pool.mu.Lock()
		retire := s.upload.retired || !s.upload.expires.IsZero() && time.Now().After(s.upload.expires)
		s.upload.pool.mu.Unlock()
		if retire {
			next, e := s.client.pool.lease()
			if e != nil {
				return
			}
			old := s.upload
			s.upload = next
			if old != s.download {
				s.client.pool.release(old)
			}
		}
		r, _ := http.NewRequestWithContext(s.ctx, x.Method, s.client.URL().String(), bytes.NewReader(b[:n]))
		if e := decorate(r, s.client.config, sid, strconv.FormatUint(seq, 10), false, rand.Reader); e != nil {
			return
		}
		if e := placePacket(r, s.client.config, b[:n], rand.Reader); e != nil {
			return
		}
		if remaining := time.Duration(interval)*time.Millisecond - time.Since(lastRequest); remaining > 0 {
			timer := time.NewTimer(remaining)
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		lastRequest = time.Now()
		resp, e := s.upload.request(r)
		if e != nil {
			return
		}
		_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		if e != nil {
			return
		}
		seq++
	}
}
func (c *Client) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		sessions := make([]*clientSession, 0, len(c.sessions))
		for s := range c.sessions {
			sessions = append(sessions, s)
		}
		c.mu.Unlock()
		c.cancel()
		for _, s := range sessions {
			s.close()
		}
		c.workers.Wait()
		c.pool.close()
		if c.downstream != nil {
			c.downstream.Close()
		}
	})
	return nil
}
