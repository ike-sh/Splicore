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
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	H "github.com/sagernet/sing/protocol/http"
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
	return []*counter{&s.stats, gen.inCounters[s.inbound], gen.outCounters[oid], gen.nodeCounters[node]}
}

// One HTTP request per local connection bounds lifetime. CONNECT retains any
// bytes already read by the upstream bounded parser, including pipelined TLS.
func (m *Manager) serveHTTP(ctx context.Context, s *session, reader *bufio.Reader, gen *snapshot) {
	header, err := readBoundedHTTPHeader(reader)
	if err != nil {
		return
	}
	reader = bufio.NewReader(io.MultiReader(bytes.NewReader(header), reader))
	req, err := H.ReadRequest(reader)
	if err != nil {
		return
	}
	defer req.Body.Close()
	fail := func(status int) {
		_, _ = fmt.Fprintf(s.local, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
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
			_, e := io.WriteString(s.local, "HTTP/1.1 200 Connection Established\r\n\r\n")
			return e
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
	stripProxyHeaders(req.Header)
	stripProxyHeaders(req.Trailer)
	req.RequestURI = ""
	req.Close = true
	req = req.WithContext(ctx)
	// No transparent HTTPS interception, redirects, or environment proxy fallback.
	_ = s.local.SetDeadline(time.Time{})
	resp, err := transport.RoundTrip(req)
	if err != nil {
		fail(502)
		return
	}
	defer resp.Body.Close()
	stripProxyHeaders(resp.Header)
	stripProxyHeaders(resp.Trailer)
	resp.Close = true
	_ = resp.Write(s.local)
}

func readBoundedHTTPHeader(reader *bufio.Reader) ([]byte, error) {
	var raw bytes.Buffer
	for {
		line, err := reader.ReadSlice('\n')
		if raw.Len()+len(line) > 64<<10 {
			return nil, fmt.Errorf("HTTP header exceeds limit")
		}
		raw.Write(line)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, err
		}
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			return raw.Bytes(), nil
		}
	}
}

func stripProxyHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "TE", "Trailer", "Upgrade"} {
		h.Del(name)
	}
}

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
	stripProxyHeaders(http.Header(header))
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
