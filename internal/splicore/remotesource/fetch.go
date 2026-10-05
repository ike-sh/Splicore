// Package remotesource bounds HTTP inputs and delegates every dial to the
// existing client runtime's protected, generation-owned network capability.
package remotesource

import (
	"bytes"
	"compress/gzip"
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Network interface {
	Resolve(context.Context, string) ([]netip.Addr, error)
	Dial(context.Context, access.Endpoint) (net.Conn, error)
}
type Result struct {
	Body               []byte
	ETag, LastModified string
	NotModified        bool
}

func failed() error { return identity.Err(identity.Unavailable, "provider fetch failed") }
func Allowed(ip netip.Addr, private bool) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return private
	}
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return ip.IsGlobalUnicast()
}
func Fetch(ctx context.Context, n Network, p provider.Provider, s provider.Source) (Result, error) {
	var result Result
	if s.Validate() != nil || n == nil {
		return result, failed()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	original, _ := provider.ValidateURL(s.URL)
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 16384, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer t.CloseIdleConnections()
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, failed()
		}
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, failed()
		}
		number, e := strconv.ParseUint(port, 10, 16)
		if e != nil || number == 0 {
			return nil, failed()
		}
		ips, e := n.Resolve(ctx, host)
		if e != nil || len(ips) == 0 || len(ips) > 32 {
			return nil, failed()
		}
		for _, ip := range ips {
			if !Allowed(ip, p.AllowPrivate) {
				return nil, failed()
			}
		}
		return n.Dial(ctx, access.Endpoint{Host: ips[0].Unmap().String(), Port: uint16(number)})
	}
	client := &http.Client{Transport: t, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return failed()
		}
		if _, e := provider.ValidateURL(req.URL.String()); e != nil {
			return failed()
		}
		if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return failed()
		}
		if req.URL.Scheme != original.Scheme || req.URL.Host != original.Host {
			req.Header.Del("Authorization")
			req.Header.Del("X-Api-Key")
			req.Header.Del("If-None-Match")
			req.Header.Del("If-Modified-Since")
		}
		return nil
	}}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if e != nil {
		return result, failed()
	}
	req.Header.Set("Accept", "application/json, text/plain, application/yaml, text/yaml")
	req.Header.Set("Accept-Encoding", "gzip")
	if s.ETag != "" {
		req.Header.Set("If-None-Match", s.ETag)
	}
	if s.LastModified != "" {
		req.Header.Set("If-Modified-Since", s.LastModified)
	}
	if a := s.Auth; a != nil {
		switch a.Type {
		case "bearer":
			req.Header.Set("Authorization", "Bearer "+a.Value)
		case "basic":
			req.SetBasicAuth(a.Username, a.Value)
		case "header":
			req.Header.Set(a.Header, a.Value)
		}
	}
	response, e := client.Do(req)
	if e != nil {
		return result, failed()
	}
	defer response.Body.Close()
	if response.StatusCode == 304 && (s.ETag != "" || s.LastModified != "") {
		result.NotModified = true
		return result, nil
	}
	if response.StatusCode != 200 {
		return result, failed()
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	switch ct {
	case "", "text/plain", "application/json", "application/yaml", "text/yaml", "text/x-yaml", "application/octet-stream":
	default:
		return result, failed()
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, provider.MaxBody+1))
	if e != nil || len(raw) > provider.MaxBody {
		return result, failed()
	}
	switch strings.ToLower(response.Header.Get("Content-Encoding")) {
	case "", "identity":
		result.Body = raw
	case "gzip":
		g, e := gzip.NewReader(bytes.NewReader(raw))
		if e != nil {
			return result, failed()
		}
		result.Body, e = io.ReadAll(io.LimitReader(g, provider.MaxBody+1))
		closeErr := g.Close()
		if e != nil || closeErr != nil || len(result.Body) > provider.MaxBody {
			return Result{}, failed()
		}
	default:
		return result, failed()
	}
	result.ETag = response.Header.Get("ETag")
	result.LastModified = response.Header.Get("Last-Modified")
	updated := s
	updated.ETag = result.ETag
	updated.LastModified = result.LastModified
	if updated.Validate() != nil {
		return Result{}, failed()
	}
	return result, nil
}
