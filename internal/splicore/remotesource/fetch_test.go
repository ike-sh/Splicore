package remotesource

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

type localNetwork struct{}

func (localNetwork) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		return []netip.Addr{ip}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
func (localNetwork) Dial(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(e.Host, fmt.Sprint(e.Port)))
}
func TestFetchLimitsTLSRedirectAuth(t *testing.T) {
	ctx := context.Background()
	p := provider.Provider{AllowPrivate: true}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "" {
			t.Error("redirect leaked auth")
		}
		io.WriteString(w, "fixture")
	}))
	defer target.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer SYNTHETIC" {
			t.Error("missing initial auth")
		}
		http.Redirect(w, r, target.URL, 302)
	}))
	defer first.Close()
	r, e := Fetch(ctx, localNetwork{}, p, provider.Source{URL: first.URL, Auth: &provider.Auth{Type: "bearer", Value: "SYNTHETIC"}})
	if e != nil || string(r.Body) != "fixture" {
		t.Fatal("redirect", e)
	}
	p.AllowPrivate = false
	if _, e = Fetch(ctx, localNetwork{}, p, provider.Source{URL: target.URL}); e == nil {
		t.Fatal("default SSRF accepted localhost")
	}
	p.AllowPrivate = true
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "fixture") }))
	defer secure.Close()
	if _, e = Fetch(ctx, localNetwork{}, p, provider.Source{URL: secure.URL}); e == nil {
		t.Fatal("TLS verification disabled")
	}
	for _, kind := range []string{"raw", "gzip", "scheme", "loop", "encoding", "content-type"} {
		t.Run(kind, func(t *testing.T) {
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "raw":
					_, _ = w.Write(bytes.Repeat([]byte("x"), provider.MaxBody+1))
				case "gzip":
					w.Header().Set("Content-Encoding", "gzip")
					g := gzip.NewWriter(w)
					_, _ = g.Write(bytes.Repeat([]byte("x"), provider.MaxBody+1))
					g.Close()
				case "scheme":
					http.Redirect(w, r, "file:///local", 302)
				case "loop":
					http.Redirect(w, r, "/again", 302)
				case "encoding":
					w.Header().Set("Content-Encoding", "br")
					io.WriteString(w, "fixture")
				case "content-type":
					w.Header().Set("Content-Type", "text/html")
					io.WriteString(w, "fixture")
				}
			}))
			defer fixture.Close()
			if _, e := Fetch(ctx, localNetwork{}, p, provider.Source{URL: fixture.URL}); e == nil {
				t.Fatal("fetch bound accepted")
			}
		})
	}
	for _, ip := range []string{"169.254.169.254", "fe80::1", "::", "224.0.0.1", "100.64.0.1", "198.18.0.1", "::ffff:169.254.169.254"} {
		if Allowed(netip.MustParseAddr(ip), true) {
			t.Fatal("unsafe destination", ip)
		}
	}
}
func FuzzURL(f *testing.F) {
	f.Add("https://user:SECRET@example.test/path/TOKEN?unknown=SECRET#SECRET")
	f.Add("file:///etc/passwd")
	f.Fuzz(func(t *testing.T, raw string) {
		redacted := provider.RedactURL(raw)
		if strings.ContainsAny(redacted, "?#@") {
			t.Fatal("URL token leaked")
		}
		_, _ = provider.ValidateURL(raw)
	})
}
