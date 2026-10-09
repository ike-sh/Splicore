// Package streamtransport adapts shared Core transports to net.Conn/net.Listener.
// It never creates outbound sockets: callers supply the approved underlay dial.
package streamtransport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

const ChunkSize = 32 << 10
const MaxMessage = 1 << 20
const HandshakeTimeout = 5 * time.Second

type DialFunc func(context.Context, string, string) (net.Conn, error)

func tlsConfig(c *tls.Config, kind string) *tls.Config {
	if c == nil {
		return nil
	}
	c = c.Clone()
	if kind == "tcp" {
		return c
	}
	if kind == "grpc" {
		c.NextProtos = []string{"h2"}
	} else {
		c.NextProtos = []string{"http/1.1"}
	}
	return c
}
func Dial(ctx context.Context, dial DialFunc, address string, c cfg.Config, tc *tls.Config) (net.Conn, error) {
	if dial == nil {
		return nil, errors.New("shared transport requires an approved dialer")
	}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if tc != nil {
		if e := c.ValidateALPN(tc.NextProtos); e != nil {
			return nil, e
		}
	}
	if c.Type() == "grpc" {
		return dialGRPC(ctx, dial, address, c, tlsConfig(tc, "grpc"))
	}
	if c.Type() == "ws" {
		admissionCtx := ctx
		var stopHandshake func() bool
		defer func() {
			if stopHandshake != nil {
				stopHandshake()
			}
		}()
		scheme := "ws"
		if tc != nil {
			scheme = "wss"
		}
		u := scheme + "://" + address + c.HTTPPath()
		h := http.Header{}
		for k, v := range c.Headers {
			h.Set(k, v)
		}
		if c.Host != "" {
			h.Set("Host", c.Host)
		}
		wd := websocket.Dialer{NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			raw, e := dial(ctx, network, address)
			if e != nil {
				return nil, e
			}
			stopHandshake = context.AfterFunc(admissionCtx, func() { raw.Close() })
			return &wsSocket{Conn: raw, limit: &headerReader{Reader: raw, n: cfg.MaxHeaders}}, nil
		}, TLSClientConfig: tlsConfig(tc, "ws"), HandshakeTimeout: HandshakeTimeout, ReadBufferSize: 4096, WriteBufferSize: ChunkSize, Proxy: nil}
		if tc != nil {
			wd.NetDialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				raw, e := dial(ctx, network, address)
				if e != nil {
					return nil, e
				}
				stopHandshake = context.AfterFunc(admissionCtx, func() { raw.Close() })
				t := tls.Client(raw, tlsConfig(tc, "ws"))
				if e = t.HandshakeContext(ctx); e != nil {
					raw.Close()
					return nil, e
				}
				return &wsSocket{Conn: t, limit: &headerReader{Reader: t, n: cfg.MaxHeaders}}, nil
			}
		}
		ws, resp, e := wd.DialContext(ctx, u, h)
		if e != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			return nil, errors.New("WebSocket transport handshake failed")
		}
		if ctx.Err() != nil {
			ws.Close()
			return nil, ctx.Err()
		}
		return newWS(ws), nil
	}
	raw, e := dial(ctx, "tcp", address)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	dl := time.Now().Add(HandshakeTimeout)
	if t, yes := ctx.Deadline(); yes && t.Before(dl) {
		dl = t
	}
	raw.SetDeadline(dl)
	var stream net.Conn = raw
	if tc != nil {
		t := tls.Client(raw, tlsConfig(tc, c.Type()))
		if e = t.HandshakeContext(ctx); e != nil {
			return nil, e
		}
		stream = t
	}
	if c.Type() == "tcp" {
		stream.SetDeadline(time.Time{})
		ok = true
		return stream, nil
	}
	if c.Type() != "httpupgrade" {
		return nil, errors.New("unsupported stream transport")
	}
	host := address
	if c.Host != "" {
		host = c.Host
	}
	u, e := url.ParseRequestURI(c.HTTPPath())
	if e != nil {
		return nil, e
	}
	req := &http.Request{Method: http.MethodGet, URL: u, Host: host, Header: http.Header{}}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if e = req.Write(stream); e != nil {
		return nil, e
	}
	limit := &headerReader{Reader: stream, n: cfg.MaxHeaders}
	br := bufio.NewReader(limit)
	resp, e := http.ReadResponse(br, req)
	if e != nil || !validUpgradeResponse(resp) {
		return nil, errors.New("HTTPUpgrade transport handshake failed")
	}
	limit.n = -1
	stream.SetDeadline(time.Time{})
	ok = true
	return &bufferedConn{Conn: stream, reader: br}, nil
}

func validUpgradeResponse(resp *http.Response) bool {
	if resp.ProtoMajor != 1 || resp.ProtoMinor != 1 || resp.StatusCode != 101 || !token(resp.Header.Get("Connection"), "upgrade") || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || resp.ContentLength > 0 || len(resp.TransferEncoding) > 0 {
		return false
	}
	if _, present := resp.Header["Transfer-Encoding"]; present {
		return false
	}
	// net/http normalizes ContentLength to zero for 1xx responses. Inspect the
	// retained header too; only a valid explicit zero is compatible with the
	// immediate switch to raw bytes. The stdlib rejects conflicting/malformed CL.
	for _, value := range resp.Header.Values("Content-Length") {
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 63)
		if err != nil || n != 0 {
			return false
		}
	}
	return true
}
func token(value, want string) bool {
	for _, t := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(t), want) {
			return true
		}
	}
	return false
}

type headerReader struct {
	io.Reader
	n int
}

func (r *headerReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, errors.New("transport headers exceed bound")
	}
	if r.n > 0 && len(p) > r.n {
		p = p[:r.n]
	}
	n, e := r.Reader.Read(p)
	if r.n > 0 {
		r.n -= n
	}
	return n, e
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *bufferedConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return errors.New("half-close unsupported")
}
