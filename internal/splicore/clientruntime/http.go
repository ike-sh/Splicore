package clientruntime

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	httpproxy "github.com/ike-sh/Splicore/internal/splicore/protocol/http"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
)

func (m *Manager) bindSelection(s *session, gen *snapshot, oid identity.ID) []*counter {
	var node identity.ID
	for _, o := range gen.state.Outbounds {
		if o.ID == oid && o.NodeID != nil {
			node = *o.NodeID
		}
	}
	m.mu.Lock()
	s.outbound, s.node, s.dialer, s.kind = oid, node, gen.outbounds[oid], "tcp"
	m.mu.Unlock()
	return []*counter{&s.stats, gen.inCounters[s.inbound], gen.outCounters[oid], gen.nodeCounters[node], gen.accountCounters[s.account]}
}

// One HTTP request per local connection bounds lifetime. CONNECT retains any
// bytes already read by the upstream bounded parser, including pipelined TLS.
func (m *Manager) serveHTTP(ctx context.Context, s *session, reader *bufio.Reader, gen *snapshot) {
	fail := func(status int) {
		m.proxyFailure(s, gen)
		challenge := ""
		if status == 407 {
			challenge = "Proxy-Authenticate: Basic realm=\"Splicore\"\r\n"
		}
		_ = socks5.WriteFull(s.local, []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n%sConnection: close\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status), challenge)))
	}
	req, next, err := httpproxy.ReadRequest(reader)
	if err != nil {
		fail(400)
		return
	}
	reader = next
	// Close the transport before Body.Close: rejected streaming bodies must never
	// be drained waiting for a client that is waiting for the rejection response.
	defer func() { _ = s.local.Close(); _ = req.Body.Close() }()
	if verify := m.proxyVerifier(s, gen); verify != nil {
		pair, e := httpproxy.Basic(req.Header.Get("Proxy-Authorization"))
		if e != nil || !verify(pair.Username, pair.Password) {
			fail(407)
			return
		}
	}
	if req.Method == http.MethodConnect {
		host, port, e := net.SplitHostPort(req.Host)
		n, parseErr := strconv.ParseUint(port, 10, 16)
		target := access.Endpoint{Host: host, Port: uint16(n)}
		if e != nil || parseErr != nil || target.Validate() != nil {
			fail(400)
			return
		}
		m.serveStream(ctx, s, gen, target, reader, func(byte) { fail(502) }, func() error {
			return socks5.WriteFull(s.local, []byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		})
		return
	}
	if req.URL.Scheme != "http" || req.URL.Host == "" || req.URL.User != nil {
		fail(400)
		return
	}
	host := req.URL.Hostname()
	port := uint64(80)
	if req.URL.Port() != "" {
		port, err = strconv.ParseUint(req.URL.Port(), 10, 16)
	}
	target := access.Endpoint{Host: host, Port: uint16(port)}
	if err != nil || target.Validate() != nil {
		fail(400)
		return
	}
	selected, resolved, err := selectRoute(ctx, gen, s.inbound, target, "tcp", nil)
	if err != nil || selected.Selected.Kind == P.Reject {
		fail(502)
		return
	}
	oid := selectedOutbound(selected.Selected)
	adapter, ok := gen.outbounds[oid].(*dialerLease)
	if !ok {
		fail(502)
		return
	}
	counters := m.bindSelection(s, gen, oid)
	transport := &http.Transport{DisableCompression: true, DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			c, err := adapter.DialContext(dialCtx, resolved)
			if err != nil {
				adapter.failed()
				return nil, err
			}
			m.mu.Lock()
			s.remote = c
			closed := m.closed || ctx.Err() != nil
			m.mu.Unlock()
			if closed {
				c.Close()
				return nil, context.Canceled
			}
			metered := &meteredConn{Conn: c, counters: counters, health: adapter}
			return &responseHeaderConn{Conn: metered, reader: bufio.NewReader(metered), headers: true}, nil
		},
	}
	defer transport.CloseIdleConnections()
	for _, c := range counters {
		if c != nil {
			c.total.Add(1)
			c.active.Add(1)
			defer c.active.Add(-1)
		}
	}
	req = forwardHTTPRequest(req)
	req.RequestURI = ""
	req.Close = true
	// After the streaming request finishes, one reader watches disconnects.
	// Canceling the transport also wakes a stalled response body.
	ctx, cancel := context.WithCancel(ctx)
	requestDone, watchDone := make(chan struct{}), make(chan struct{})
	body := &requestBody{ReadCloser: req.Body, done: requestDone}
	if req.Body == http.NoBody {
		body.finish()
	} else {
		req.Body = body
	}
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			return
		case <-requestDone:
		}
		_, _ = io.Copy(io.Discard, reader)
		cancel()
	}()
	defer func() { cancel(); _ = s.local.Close(); <-watchDone }()
	req = req.WithContext(ctx)
	// No transparent HTTPS interception, redirects, or environment proxy fallback.
	_ = s.local.SetDeadline(time.Time{})
	resp, err := transport.RoundTrip(req)
	if err != nil {
		fail(502)
		return
	}
	defer resp.Body.Close()
	// Response trailers have the same late-population ownership requirement.
	out := new(http.Response)
	*out = *resp
	out.Header = resp.Header.Clone()
	out.Trailer = forwardHTTPTrailers(resp.Header, resp.Trailer)
	out.Body = forwardHTTPBody(resp.Body, resp.Trailer, out.Trailer)
	stripProxyHeaders(out.Header)
	out.Close = true
	if err = out.Write(s.local); err != nil && ctx.Err() == nil {
		m.proxyFailure(s, gen)
	}
}

type requestBody struct {
	io.ReadCloser
	done chan struct{}
	once sync.Once
}

func (b *requestBody) finish() { b.once.Do(func() { close(b.done) }) }
func (b *requestBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if e == io.EOF {
		b.finish()
	}
	return n, e
}
func (b *requestBody) Close() error { e := b.ReadCloser.Close(); b.finish(); return e }

func readBoundedHTTPHeader(r *bufio.Reader) ([]byte, error) { return httpproxy.ReadHeader(r) }
func stripProxyHeaders(h http.Header)                       { httpproxy.StripHeaders(h) }

type meteredConn struct {
	net.Conn
	counters []*counter
	health   *dialerLease
}

// net/http removes Connection: close during parsing. Remove every nominated
// field first, while the original bounded response header is still available.
type responseHeaderConn struct {
	net.Conn
	reader  *bufio.Reader
	pending *bytes.Reader
	headers bool
}

func (c *responseHeaderConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.pending != nil && c.pending.Len() > 0 {
		return c.pending.Read(p)
	}
	if !c.headers {
		return c.reader.Read(p)
	}
	raw, err := readBoundedHTTPHeader(c.reader)
	if err != nil {
		return 0, err
	}
	parsed := bufio.NewReader(bytes.NewReader(raw))
	status, err := parsed.ReadString('\n')
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(status)
	if len(fields) < 2 {
		return 0, fmt.Errorf("invalid HTTP response status")
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil || code < 100 || code > 999 {
		return 0, fmt.Errorf("invalid HTTP response status")
	}
	header, err := textproto.NewReader(parsed).ReadMIMEHeader()
	if err != nil {
		return 0, err
	}
	closeConnection := false
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "close") {
				closeConnection = true
			}
		}
	}
	// Preserve safe trailer declarations for the response parser. Late values
	// are copied separately by forwardHTTPBody; nominated fields stay excluded.
	declared := make(http.Header)
	for _, value := range header.Values("Trailer") {
		for _, name := range strings.Split(value, ",") {
			declared[strings.TrimSpace(name)] = nil
		}
	}
	trailers := forwardHTTPTrailers(http.Header(header), declared)
	stripProxyHeaders(http.Header(header))
	for name := range trailers {
		header.Add("Trailer", name)
	}
	if closeConnection {
		header.Set("Connection", "close")
	}
	var filtered bytes.Buffer
	filtered.WriteString(status)
	if err = http.Header(header).Write(&filtered); err != nil {
		return 0, err
	}
	filtered.WriteString("\r\n")
	c.headers = code >= 100 && code < 200 && code != 101
	c.pending = bytes.NewReader(filtered.Bytes())
	return c.pending.Read(p)
}

func (c *meteredConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	for _, v := range c.counters {
		if v != nil {
			v.download.Add(int64(n))
		}
	}
	if n > 0 {
		c.health.success()
	}
	return n, e
}
func (c *meteredConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	for _, v := range c.counters {
		if v != nil {
			v.upload.Add(int64(n))
		}
	}
	return n, e
}
