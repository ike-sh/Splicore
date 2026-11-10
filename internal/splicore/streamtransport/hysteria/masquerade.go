package hysteria

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
)

type proxyBuffers struct{ buffers chan []byte }

func (p *proxyBuffers) Get() []byte {
	select {
	case b := <-p.buffers:
		return b
	default:
		return make([]byte, 32<<10)
	}
}
func (p *proxyBuffers) Put(b []byte) {
	if cap(b) != 32<<10 {
		return
	}
	select {
	case p.buffers <- b[:32<<10]:
	default:
	}
}

// net/http detaches dialing from request cancellation for connection pooling.
// Keep the initiating request's deadline/cancellation available to the approved
// dialer, while retaining the transport's own cancellation and server ownership.
type masqueradeRequestContext struct{}
type masqueradeTransport struct{ *http.Transport }

func (t masqueradeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := context.WithValue(r.Context(), masqueradeRequestContext{}, r.Context())
	return t.Transport.RoundTrip(r.WithContext(ctx))
}

func masquerade(m *cfg.Masquerade, dial func(context.Context, string, string) (net.Conn, error)) (http.Handler, func(), error) {
	noop := func() {}
	if m == nil || m.Type == "" || m.Type == "404" {
		return http.HandlerFunc(http.NotFound), noop, nil
	}
	if e := m.Validate(); e != nil {
		return nil, nil, e
	}
	switch m.Type {
	case "string":
		snapshot := *m
		snapshot.Headers = m.Headers // caller supplies an owned deep clone
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range snapshot.Headers {
				w.Header().Set(k, v)
			}
			status := snapshot.Status
			if status == 0 {
				status = 200
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(snapshot.Content))
		}), noop, nil
	case "file":
		root, e := os.OpenRoot(m.Directory)
		if e != nil {
			return nil, nil, e
		}
		return http.FileServerFS(root.FS()), func() { _ = root.Close() }, nil
	case "proxy":
		if dial == nil {
			return nil, nil, fmt.Errorf("%w: proxy masquerade requires an approved upstream dialer", ErrConfig)
		}
		target, _ := url.Parse(m.URL)
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: m.Insecure}, MaxIdleConns: 16, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 64, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10}
		owner := clientio.New()
		connect := func(ctx context.Context, network, address string, secure bool) (net.Conn, error) {
			request, ok := ctx.Value(masqueradeRequestContext{}).(context.Context)
			if !ok {
				return nil, ErrConfig
			}
			admission, cancel := context.WithTimeout(request, 5*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, cancel)
			defer stop()
			admission, done, e := owner.Begin(admission)
			if e != nil {
				return nil, e
			}
			defer done()
			raw, e := dial(admission, network, address)
			if e != nil {
				return nil, e
			}
			raw, e = owner.Conn(raw)
			if e != nil {
				return nil, e
			}
			if e = admission.Err(); e != nil {
				_ = raw.Close()
				return nil, e
			}
			if !secure {
				return raw, nil
			}
			tc := tr.TLSClientConfig.Clone()
			tc.ServerName, _, e = net.SplitHostPort(address)
			if e != nil {
				_ = raw.Close()
				return nil, e
			}
			secured := tls.Client(raw, tc)
			if e = secured.HandshakeContext(admission); e != nil {
				_ = secured.Close()
				return nil, e
			}
			return secured, nil
		}
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return connect(ctx, network, address, false)
		}
		tr.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return connect(ctx, network, address, true)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		director := proxy.Director
		rewrite := m.RewriteHost
		proxy.Director = func(r *http.Request) {
			director(r)
			if rewrite {
				r.Host = target.Host
			}
			for k := range r.Header {
				if len(k) >= 9 && http.CanonicalHeaderKey(k)[:9] == "Hysteria-" {
					r.Header.Del(k)
				}
			}
		}
		proxy.Transport = masqueradeTransport{tr}
		proxy.ModifyResponse = func(r *http.Response) error {
			for k := range r.Header {
				if len(k) >= 9 && http.CanonicalHeaderKey(k)[:9] == "Hysteria-" {
					r.Header.Del(k)
				}
			}
			if r.StatusCode == 233 {
				r.StatusCode = http.StatusBadGateway
				r.Status = "502 Bad Gateway"
			}
			return nil
		}
		proxy.BufferPool = &proxyBuffers{make(chan []byte, 16)}
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("Hysteria masquerade upstream: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}
		return proxy, func() { owner.Close(); tr.CloseIdleConnections() }, nil
	}
	return nil, nil, ErrConfig
}
