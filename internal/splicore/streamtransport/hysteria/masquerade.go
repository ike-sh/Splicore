package hysteria

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
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
func masquerade(m *cfg.Masquerade) (http.Handler, func(), error) {
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
		target, _ := url.Parse(m.URL)
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: m.Insecure}, MaxIdleConns: 16, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 64, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10}
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
		proxy.Transport = tr
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
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}
		return proxy, tr.CloseIdleConnections, nil
	}
	return nil, nil, ErrConfig
}
