//go:build with_quic

package session

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

func TestHTTPAbuseAndReservedICMPIsolation(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		t.Run(mode, func(t *testing.T) {
			a, tc, _ := startServer(t, mode, nil)
			c := newClient(t, mode, a, tc, nil)
			s, e := c.acquire(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			for _, method := range []string{"GET", "POST", "CONNECT"} {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				req := (&http.Request{Method: method, URL: &url.URL{Scheme: "https", Host: "example.test:443", Path: "/invalid"}, Host: "example.test:443", Header: c.headers("example.test:443")}).WithContext(ctx)
				var resp *http.Response
				if mode == "http2" {
					resp, e = s.raw.(*h2Connection).client.RoundTrip(req)
				} else {
					raw, err := s.raw.(*h3Connection).client.OpenRequestStream(ctx)
					if err != nil {
						t.Fatal(err)
					}
					e = raw.SendRequestHeader(req)
					if e == nil {
						resp, e = raw.ReadResponse()
					}
					raw.CancelRead(0x10c)
					raw.CancelWrite(0x10c)
				}
				if resp != nil {
					resp.Body.Close()
				}
				cancel()
				if e == nil && resp.StatusCode == 200 {
					t.Fatal("invalid request accepted", method)
				}
			}
			first, e := c.openSession(context.Background(), s, "_icmp")
			if e != nil {
				t.Fatal(e)
			}
			if raw, e := s.raw.open(context.Background(), "_icmp", c.headers("_icmp")); e == nil {
				raw.Close()
				t.Fatal("duplicate ICMP admitted")
			}
			first.Close()
			// HTTP libraries reject an excessive response/request header list before
			// the handler can create target state. The auth header remains owned.
			h := c.headers("_check")
			h.Set("User-Agent", strings.Repeat("x", maxHeaders*2))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if raw, e := s.raw.open(ctx, "_check", h); e == nil {
				raw.Close()
				t.Fatal("oversized header admitted")
			}
		})
	}
}

func TestAuthenticationCloseCodeClassification(t *testing.T) {
	for _, e := range []error{http2.GoAwayError{ErrCode: 0x1f}, http2.StreamError{Code: 0x1f}, &quic.ApplicationError{ErrorCode: 0x1f}, &quic.StreamError{ErrorCode: 0x1f}} {
		if !IsCode(classify(HTTP, e), Auth) {
			t.Fatal(e)
		}
	}
	if !IsCode(classify(QUIC, &quic.TransportError{ErrorCode: 0x178}), ALPN) {
		t.Fatal("QUIC ALPN alert")
	}
}

func TestH2ALPNMismatch(t *testing.T) {
	var pair tls.Certificate
	_, tc, _ := startServer(t, "http2", func(cfg *ServerConfig) { pair = cfg.TLS.Certificates[0] })
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, e := l.Accept()
		if e != nil {
			return
		}
		defer n.Close()
		_ = n.SetDeadline(time.Now().Add(time.Second))
		_ = tls.Server(n, &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}).Handshake()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, e := newH2(ctx, ctx, ClientConfig{TLS: tc, DialTCP: (&net.Dialer{}).DialContext}, l.Addr().String())
	if raw != nil {
		raw.close()
	}
	<-done
	if !IsCode(e, ALPN) {
		t.Fatal("ALPN mismatch classification", e)
	}
}
