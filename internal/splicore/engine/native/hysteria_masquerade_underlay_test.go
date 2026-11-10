package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

// Exercise native Start -> backend -> shared masquerade using the production
// underlay factory and the existing fake-host/socket-control fixture. TLS is
// loaded as owned test material; private-file Compile qualification is separate.
func TestNativeHysteriaMasqueradeProtectedUnderlay(t *testing.T) {
	var ambientDNS atomic.Int64
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		ambientDNS.Add(1)
		return nil, errors.New("unexpected ambient resolver")
	}}
	defer func() {
		net.DefaultResolver = previous
		if ambientDNS.Load() != 0 {
			t.Errorf("ambient DNS calls=%d", ambientDNS.Load())
		}
	}()
	for _, mode := range []string{"http4", "http6", "https4", "protected-refusal", "dns-refusal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fixture := newMasqueradeUnderlay(t)
			lease, err := fixture.Factory.Begin(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := lease.Close(); err != nil {
					t.Error(err)
				}
			})
			runtime, _ := identity.NewID()
			scope := underlay.Scope{Purpose: underlay.ServerTarget, Runtime: runtime, Generation: lease.ID}
			protected, err := fixture.Factory.New(scope)
			if err != nil {
				t.Fatal(err)
			}
			var upstreamCalls atomic.Int64
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				if r.Header.Get("Hysteria-Auth") != "" {
					t.Error("authentication header leaked")
				}
				_, _ = io.WriteString(w, "protected-native-response")
			}))
			if mode == "http6" {
				_ = upstream.Listener.Close()
				upstream.Listener, err = net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "https4" {
				upstream.StartTLS()
			} else {
				upstream.Start()
			}
			defer upstream.Close()
			url := upstream.URL
			if mode == "dns-refusal" {
				url = "http://must-use-protected-dns.invalid/"
			}
			material := masqueradeTLS(t)
			pair, err := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			owner, stop := context.WithCancel(context.Background())
			h := &hysteria2Handle{ctx: owner, cancel: stop, endpoint: access.Endpoint{Host: "127.0.0.1"}, protected: protected, tls: &tls.Config{Certificates: []tls.Certificate{pair}}, transport: cfg.Hysteria{Version: 2, Masquerade: &cfg.Masquerade{Type: "proxy", URL: url, Insecure: mode == "https4"}}}
			t.Cleanup(func() {
				closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := h.Close(closeCtx); err != nil {
					t.Error(err)
				}
			})
			if err = h.Start(ctx); err != nil {
				t.Fatal(err)
			}
			h.Activate()
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			transport := &quic.Transport{Conn: packet}
			defer transport.Close()
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(material.CACertificate)) {
				t.Fatal("fixture CA")
			}
			q, err := transport.Dial(ctx, h.server.Addr(), &tls.Config{RootCAs: pool, ServerName: material.ServerName, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			defer q.CloseWithError(0, "")
			h3 := &http3.Transport{}
			defer h3.Close()
			client := h3.NewClientConn(q)
			if mode == "protected-refusal" {
				fixture.Backend.SetFailure(0, true)
			}
			r, err := http.NewRequestWithContext(ctx, "GET", "https://ordinary.invalid/masquerade", nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Hysteria-Auth", "not-forwarded")
			response, err := client.RoundTrip(r)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			refusal := mode == "protected-refusal" || mode == "dns-refusal"
			if refusal {
				if response.StatusCode != 502 || upstreamCalls.Load() != 0 || fixture.Backend.Count(underlay.ServerTarget) != 0 {
					t.Fatal("unprotected fallback after refusal", response.StatusCode, upstreamCalls.Load())
				}
			} else {
				if response.StatusCode != 200 || string(body) != "protected-native-response" || upstreamCalls.Load() != 1 || fixture.Backend.Count(underlay.ServerTarget) != 1 {
					t.Fatal("native protected path missing", response.StatusCode, string(body), fixture.Backend.SnapshotEvents())
				}
				for _, event := range fixture.Backend.SnapshotEvents() {
					if event.Scope != scope || event.Address != upstream.Listener.Addr().String() {
						t.Fatal("incorrect protected scope/target", event)
					}
				}
			}
			fixture.Backend.SetFailure(0, false)
			if err = h.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
