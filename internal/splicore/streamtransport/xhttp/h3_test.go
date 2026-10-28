//go:build with_quic

package xhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

func h3Fixture(t *testing.T, c cfg.Config) (*Client, *Listener, *atomic.Int32) {
	t.Helper()
	p, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, client := tlsPair(t)
	server.NextProtos, client.NextProtos = []string{"h3"}, []string{"h3"}
	sc := c.Clone()
	if sc.XHTTP != nil {
		sc.XHTTP.XMUX = nil
		sc.XHTTP.Download = nil
		sc.XHTTP.Interval = cfg.Range{}
		sc.XHTTP.Chunk = cfg.Range{}
		sc.XHTTP.NoGRPC = false
		sc.XHTTP.SessionTable = ""
		sc.XHTTP.SessionLength = cfg.Range{}
	}
	ln, err := NewPacketListener(p, sc, server)
	if err != nil {
		p.Close()
		t.Fatal(err)
	}
	l := ln.(*Listener)
	count := &atomic.Int32{}
	socket := func(context.Context) (net.PacketConn, net.Addr, error) {
		p, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err == nil {
			count.Add(1)
		}
		return p, l.base.(*packetListener).PacketConn.LocalAddr(), err
	}
	cl, err := NewClient(func(context.Context, string, string) (net.Conn, error) {
		t.Error("H3 attempted TCP dial")
		return nil, net.ErrClosed
	}, l.Addr().String(), c, Security{TLS: client, PacketSocket: socket}, nil)
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close(); l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return cl, l, count
}

func TestXHTTPH3ModesPayloadIsolationAndReuse(t *testing.T) {
	for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			cl, l, count := h3Fixture(t, cfg.Config{Kind: "xhttp", Path: "/h3?fixed=1", Host: "authority.synthetic.test", XHTTP: &cfg.XHTTP{Mode: mode, XMUX: &cfg.XMUX{MaxConnections: cfg.Range{Min: 1, Max: 1}}}})
			conns := make([]net.Conn, 8)
			for i := range conns {
				c, err := cl.DialContext(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				conns[i] = c
				defer c.Close()
			}
			conns[0].Close()
			var wg sync.WaitGroup
			for i := 1; i < len(conns); i++ {
				wg.Go(func() { exchange(t, conns[i], bytes.Repeat([]byte{byte(i)}, 65537)) })
			}
			wg.Wait()
			for _, size := range []int{1, 53, 32768, 3 << 20} {
				exchange(t, conns[1], bytes.Repeat([]byte{byte(size % 251)}, size))
			}
			if count.Load() != 1 {
				t.Fatal("H3 failed connection reuse", count.Load())
			}
			cl.Close()
			l.Close()
			l.mu.Lock()
			defer l.mu.Unlock()
			if len(l.sessions) != 0 || l.pending != 0 || l.receiving != 0 {
				t.Fatal("retained H3 session resources")
			}
			h3ReclaimClosedPacket(t, l.base.(*packetListener).PacketConn)
		})
	}
}

func TestXHTTPH3MetadataPaddingAndData(t *testing.T) {
	var configs []cfg.Config
	for _, sid := range []string{"path", "query", "header", "cookie"} {
		for _, seq := range []string{"path", "query", "header", "cookie"} {
			configs = append(configs, cfg.Config{Kind: "xhttp", Path: "/metadata", XHTTP: &cfg.XHTTP{Mode: "packet-up", SessionPlacement: sid, SequencePlacement: seq}})
		}
	}
	for _, place := range []string{"query", "header", "cookie", "queryInHeader"} {
		for _, method := range []string{"repeat-x", "tokenish"} {
			configs = append(configs, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{PaddingObfs: true, PaddingPlacement: place, PaddingMethod: method, Padding: cfg.Range{Min: 64, Max: 64}}})
		}
	}
	for _, place := range []string{"body", "auto", "header", "cookie"} {
		for _, method := range []string{"POST", "GET", "PUT", "PATCH", "DELETE"} {
			configs = append(configs, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "packet-up", DataPlacement: place, Method: method}})
		}
	}
	for i, config := range configs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			cl, _, _ := h3Fixture(t, config)
			c, err := cl.DialContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			exchange(t, c, bytes.Repeat([]byte("metadata"), 2200))
		})
	}
}

func TestXHTTPH3ALPNAndCertificateFailures(t *testing.T) {
	cl, l, _ := h3Fixture(t, cfg.Config{Kind: "xhttp"})
	for _, alpn := range []string{"h2", "http/1.1", cfg.GenericQUICALPN, "invalid"} {
		t.Run(alpn, func(t *testing.T) {
			p, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			tr := &quic.Transport{Conn: p}
			defer tr.Close()
			tc := cl.security.TLS.Clone()
			tc.NextProtos = []string{alpn}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			q, err := tr.Dial(ctx, l.base.(*packetListener).LocalAddr(), tc, h3QUICConfig(false, -1))
			if err == nil {
				q.CloseWithError(0, "test")
				t.Fatal("accepted wrong ALPN")
			}
		})
	}
	for _, failure := range []string{"wrong-sni", "untrusted-ca"} {
		t.Run(failure, func(t *testing.T) {
			tc := cl.security.TLS.Clone()
			if failure == "wrong-sni" {
				tc.ServerName = "wrong.synthetic.test"
			} else {
				tc.RootCAs = nil
			}
			tr := newH3Transport(Security{TLS: tc, PacketSocket: cl.security.PacketSocket}, -1).(*h3Transport)
			defer tr.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			r, _ := http.NewRequestWithContext(ctx, "GET", cl.URL().String(), nil)
			resp, err := tr.RoundTrip(r)
			if err == nil {
				resp.Body.Close()
				t.Fatal("accepted invalid certificate")
			}
		})
	}
}

func TestXHTTPH3BlockedWriteCloseAndRestart(t *testing.T) {
	for range 5 {
		cl, l, _ := h3Fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "stream-one"}})
		c, err := cl.DialContext(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := io.CopyN(c, zeroReader{}, 64<<20); done <- err }()
		// The echo response is deliberately unread: the receive window fills,
		// then response/request backpressure reaches the logical writer.
		time.Sleep(30 * time.Millisecond)
		c.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("unread response did not impose backpressure")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("close retained a blocked writer")
		}
		cl.Close()
		l.Close()
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestXHTTPH3AdmissionAndStatusFailures(t *testing.T) {
	cl, l, _ := h3Fixture(t, cfg.Config{Kind: "xhttp", Path: "/exact", Host: "authority.synthetic.test"})
	entry, err := cl.pool.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer cl.pool.release(entry)
	for _, variant := range []string{"path", "host", "connect"} {
		t.Run(variant, func(t *testing.T) {
			u := cl.URL()
			method := "GET"
			switch variant {
			case "path":
				u.Path = "/wrong"
			case "host":
				u.Host = "wrong.synthetic.test"
			case "connect":
				method = "CONNECT"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r, _ := http.NewRequestWithContext(ctx, method, u.String(), nil)
			if err := decorate(r, cl.config, "550e8400-e29b-41d4-a716-446655440000", "", false, bytes.NewReader(bytes.Repeat([]byte{1}, 2048))); err != nil {
				t.Fatal(err)
			}
			resp, err := entry.request(r)
			if err == nil {
				resp.Body.Close()
				t.Fatal("accepted wrong endpoint")
			}
		})
	}
	l.Close()
	if _, err := cl.DialContext(context.Background()); err == nil {
		t.Fatal("accepted closed peer")
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed listener accept", err)
	}
}

func TestXHTTPH3PacketReorderReplayAndHeaders(t *testing.T) {
	cl, l, _ := h3Fixture(t, cfg.Config{Kind: "xhttp", Path: "/sequence", XHTTP: &cfg.XHTTP{Mode: "packet-up"}})
	c, err := cl.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cl.mu.Lock()
	var session *clientSession
	for s := range cl.sessions {
		session = s
	}
	cl.mu.Unlock()
	send := func(seq string, body []byte, extra bool) int {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r, _ := http.NewRequestWithContext(ctx, "POST", cl.URL().String(), bytes.NewReader(body))
		if err := decorate(r, cl.config, session.id, seq, false, bytes.NewReader(bytes.Repeat([]byte{1}, 4096))); err != nil {
			t.Fatal(err)
		}
		if extra {
			r.Header.Set("X-Oversized", string(bytes.Repeat([]byte{'X'}, 32768)))
		}
		resp, err := session.upload.transport.RoundTrip(r)
		if err != nil {
			return 0 // Oversized HEADERS may reset the request stream.
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	for _, n := range []int{2, 0, 1} {
		if status := send(strconv.Itoa(n), []byte{byte('A' + n)}, false); status != 200 {
			t.Fatal("reordered packet rejected", status)
		}
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	body := make([]byte, 3)
	if _, err := io.ReadFull(c, body); err != nil || string(body) != "ABC" {
		t.Fatal("out of order delivery", string(body), err)
	}
	for _, seq := range []string{"2", "-1", "18446744073709551616", "4096"} {
		if status := send(seq, []byte("replay"), false); status == 200 {
			t.Fatal("accepted replay/malformed/gap", seq)
		}
	}
	if send("3", []byte("header-bomb"), true) == 200 {
		t.Fatal("H3 header limit absent")
	}
	l.mu.Lock()
	if l.pending > totalBytes {
		t.Fatal("packet buffer exceeds aggregate limit")
	}
	l.mu.Unlock()
}

func TestXHTTPH3SocketLeakOracle(t *testing.T) {
	retained, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	if errors.Is(retained.SetDeadline(time.Time{}), net.ErrClosed) {
		t.Fatal("oracle missed deliberately retained UDP socket")
	}
	retained.Close()
	h3ReclaimClosedPacket(t, retained)
	for range 8 {
		cl, l, _ := h3Fixture(t, cfg.Config{Kind: "xhttp"})
		c, err := cl.DialContext(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		exchange(t, c, []byte("lifecycle"))
		entry := cl.pool.entries[0].transport.(*h3Transport)
		entry.mu.Lock()
		var sockets []*h3Socket
		for socket := range entry.sockets {
			sockets = append(sockets, socket)
		}
		entry.mu.Unlock()
		c.Close()
		cl.Close()
		l.Close()
		h3ReclaimBound(t, entry, 0, 0, 0)
		for _, socket := range sockets {
			h3ReclaimRetiredSocket(t, entry, socket)
		}
		h3ReclaimClosedPacket(t, l.base.(*packetListener).PacketConn)
	}
}

func TestXHTTPH3RequestConcurrencyBound(t *testing.T) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	cl, l, _ := h3Fixture(t, cfg.Config{Kind: "xhttp"})
	entry, err := cl.pool.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer cl.pool.release(entry)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var workers sync.WaitGroup
	for i := range 144 {
		workers.Go(func() {
			r, _ := http.NewRequestWithContext(ctx, "GET", cl.URL().String(), nil)
			id := fmt.Sprintf("550e8400-e29b-41d4-a716-%012d", i)
			if err := decorate(r, cl.config, id, "", false, bytes.NewReader(bytes.Repeat([]byte{1}, 4096))); err != nil {
				t.Error(err)
				return
			}
			resp, err := entry.transport.RoundTrip(r)
			if err == nil {
				<-ctx.Done()
				resp.Body.Close()
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	l.mu.Lock()
	sessions := len(l.sessions)
	l.mu.Unlock()
	if sessions == 0 || sessions > 128 {
		t.Fatal("HTTP/3 concurrent request stream bound", sessions)
	}
	cancel()
	workers.Wait()
	cl.Close()
	l.Close()
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("144 attempted requests; concurrent sessions=%d; heap before=%d after=%d; goroutines=%d", sessions, before.HeapAlloc, after.HeapAlloc, runtime.NumGoroutine())
	if after.HeapAlloc > before.HeapAlloc+64<<20 {
		t.Fatal("retained request state exceeds bounded stress budget")
	}
}

type h3LossPacket struct {
	net.PacketConn
	count atomic.Uint32
}

func (p *h3LossPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	count := p.count.Add(1)
	if count%17 == 0 {
		return len(b), nil
	}
	if count%7 == 0 {
		time.Sleep(time.Millisecond)
	}
	return p.PacketConn.WriteTo(b, addr)
}

func TestXHTTPH3LossAndLatency(t *testing.T) {
	cl, _, _ := h3Fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "stream-one"}})
	original := cl.security.PacketSocket
	cl.security.PacketSocket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, addr, err := original(ctx)
		if err != nil {
			return nil, nil, err
		}
		return &h3LossPacket{PacketConn: p}, addr, nil
	}
	c, err := cl.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	exchange(t, c, bytes.Repeat([]byte("lossy H3"), 150000))
}

func TestXHTTPH3XMUXRetirement(t *testing.T) {
	for _, control := range []string{"concurrency", "connections", "reuse", "requests", "lifetime", "keepalive-disabled"} {
		t.Run(control, func(t *testing.T) {
			m := &cfg.XMUX{MaxConnections: cfg.Range{Min: 1, Max: 1}}
			switch control {
			case "concurrency":
				m.MaxConnections = cfg.Range{}
				m.MaxConcurrency = cfg.Range{Min: 1, Max: 1}
			case "connections":
				m.MaxConnections = cfg.Range{Min: 2, Max: 2}
			case "reuse":
				m.Reuse = cfg.Range{Min: 1, Max: 1}
			case "requests":
				m.Requests = cfg.Range{Min: 2, Max: 2}
			case "lifetime":
				m.Lifetime = cfg.Range{Min: 1, Max: 1}
			case "keepalive-disabled":
				m.KeepAlive = -1
			}
			cl, _, _ := h3Fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "packet-up", XMUX: m}})
			a, e := cl.DialContext(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			exchange(t, a, []byte("first"))
			if control == "lifetime" {
				time.Sleep(1100 * time.Millisecond)
			}
			b, e := cl.DialContext(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close()
			exchange(t, b, []byte("second"))
			a.Close()
			exchange(t, b, []byte("other session continues"))
			cl.pool.mu.Lock()
			entries := len(cl.pool.entries)
			cl.pool.mu.Unlock()
			if control != "keepalive-disabled" && entries < 2 {
				t.Fatal("pool limit/retirement not applied", control, entries)
			}
			cl.Close()
			if len(cl.pool.entries) != 0 {
				t.Fatal("pool retained after close")
			}
		})
	}
}

func TestXHTTPH3DownloadAcrossCarriers(t *testing.T) {
	for _, upload := range []int{1, 2, 3} {
		for _, download := range []int{1, 2, 3} {
			if upload != 3 && download != 3 {
				continue
			}
			for _, mode := range []string{"auto", "packet-up", "stream-up"} {
				t.Run(fmt.Sprintf("h%d-h%d/%s", upload, download, mode), func(t *testing.T) {
					m := testkit.TLSForName(t, "split.synthetic.test")
					pair, err := tls.LoadX509KeyPair(m.CertificateFile, m.PrivateKeyFile)
					if err != nil {
						t.Fatal(err)
					}
					roots := x509.NewCertPool()
					roots.AppendCertsFromPEM([]byte(m.CACertificate))
					serverTLS := &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
					clientTLS := &tls.Config{RootCAs: roots, ServerName: m.ServerName, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
					p, err := net.ListenPacket("udp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					tr := cfg.Config{Kind: "xhttp", Path: "/split"}
					ln, err := NewPacketListener(p, tr, serverTLS)
					if err != nil {
						p.Close()
						t.Fatal(err)
					}
					l := ln.(*Listener)
					defer l.Close()
					go func() {
						for {
							c, e := l.Accept()
							if e != nil {
								return
							}
							go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
						}
					}()
					front, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					httpServer := &http.Server{Handler: l, ReadHeaderTimeout: time.Second}
					defer httpServer.Close()
					secureTCP := upload == 2 || download == 2
					if secureTCP {
						tc := serverTLS.Clone()
						tc.NextProtos = []string{"h2"}
						if err = http2.ConfigureServer(httpServer, &http2.Server{}); err != nil {
							t.Fatal(err)
						}
						go httpServer.Serve(tls.NewListener(front, tc))
					} else {
						go httpServer.Serve(front)
					}
					security := func(version int) Security {
						if version == 1 {
							return Security{}
						}
						tc := clientTLS.Clone()
						if version == 2 {
							tc.NextProtos = []string{"h2"}
							return Security{TLS: tc}
						}
						return Security{TLS: tc, PacketSocket: func(context.Context) (net.PacketConn, net.Addr, error) {
							p, e := net.ListenPacket("udp4", "127.0.0.1:0")
							return p, l.Addr(), e
						}}
					}
					endpoint := func(version int) access.Endpoint {
						addr := front.Addr()
						if version == 3 {
							addr = l.Addr()
						}
						_, port, _ := net.SplitHostPort(addr.String())
						n, _ := strconv.Atoi(port)
						return access.Endpoint{Host: "127.0.0.1", Port: uint16(n)}
					}
					d := cfg.Download{Endpoint: endpoint(download), Transport: tr, Security: "none"}
					if download > 1 {
						alpn := "h2"
						if download == 3 {
							alpn = "h3"
						}
						d.Security = "tls"
						d.TLS = access.ClientTLS{Enabled: true, ServerName: m.ServerName, Trust: "explicit_ca", CACertificate: m.CACertificate, ALPN: []string{alpn}}
					}
					cc := tr.Clone()
					cc.XHTTP = &cfg.XHTTP{Mode: mode, Download: &d}
					up := endpoint(upload)
					cl, err := NewClient((&net.Dialer{}).DialContext, net.JoinHostPort(up.Host, strconv.Itoa(int(up.Port))), cc, security(upload), func(cfg.Download) (Security, error) { return security(download), nil })
					if err != nil {
						t.Fatal(err)
					}
					defer cl.Close()
					c, err := cl.DialContext(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					exchange(t, c, bytes.Repeat([]byte("split H3 carrier"), 10000))
				})
			}
		}
	}
}

func TestXHTTPH3IdleAndHandshakeCancellation(t *testing.T) {
	cl, _, _ := h3Fixture(t, cfg.Config{Kind: "xhttp"})
	tr := newH3Transport(cl.security, -1).(*h3Transport)
	defer tr.Close()
	tr.QUICConfig.MaxIdleTimeout = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q, err := tr.dial(ctx, "", tr.TLSClientConfig, tr.QUICConfig)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-q.Context().Done():
	case <-ctx.Done():
		t.Fatal("idle connection retained")
	}
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	var handshake net.PacketConn
	sec := cl.security
	sec.PacketSocket = func(context.Context) (net.PacketConn, net.Addr, error) {
		p, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e == nil {
			handshake = p
		}
		return p, blackhole.LocalAddr(), e
	}
	blocked := newH3Transport(sec, -1).(*h3Transport)
	done := make(chan error, 1)
	go func() {
		_, e := blocked.dial(context.Background(), "", blocked.TLSClientConfig, blocked.QUICConfig)
		done <- e
	}()
	time.Sleep(30 * time.Millisecond)
	blocked.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled handshake accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake close blocked")
	}
	if handshake == nil {
		t.Fatal("no handshake socket created")
	}
	h3ReclaimClosedPacket(t, handshake)
	h3ReclaimBound(t, blocked, 0, 0, 0)
}

func TestXHTTPH3RapidRestartCertificateRotation(t *testing.T) {
	before := runtime.NumGoroutine()
	for range 8 {
		// Each listener owns a fresh socket. Certificate rotation requires a
		// fresh handshake, not reacquisition of a released ephemeral port.
		p, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal("restart socket", err)
		}
		server, client := tlsPair(t)
		server.NextProtos = []string{"h3"}
		client.NextProtos = []string{"h3"}
		ln, e := NewPacketListener(p, cfg.Config{Kind: "xhttp"}, server)
		if e != nil {
			p.Close()
			t.Fatal(e)
		}
		tr := newH3Transport(Security{TLS: client, PacketSocket: func(context.Context) (net.PacketConn, net.Addr, error) {
			p, e := net.ListenPacket("udp4", "127.0.0.1:0")
			return p, ln.Addr(), e
		}}, -1).(*h3Transport)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		q, e := tr.dial(ctx, "", tr.TLSClientConfig, tr.QUICConfig)
		cancel()
		if e != nil {
			tr.Close()
			ln.Close()
			t.Fatal("new certificate handshake", e)
		}
		if q.ConnectionState().TLS.DidResume {
			t.Fatal("unexpected QUIC TLS session resumption")
		}
		ln.Close()
		tr.Close()
		h3ReclaimClosedPacket(t, p)
		h3ReclaimBound(t, tr, 0, 0, 0)
		if q.Context().Err() == nil {
			t.Fatal("restart retained old QUIC connection")
		}
	}
	until := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+8 && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if runtime.NumGoroutine() > before+8 {
		t.Fatal("H3 shutdown goroutines retained", before, runtime.NumGoroutine())
	}
}

func TestXHTTPH3Keepalive(t *testing.T) {
	cl, _, _ := h3Fixture(t, cfg.Config{Kind: "xhttp"})
	tr := newH3Transport(cl.security, 1).(*h3Transport)
	defer tr.Close()
	tr.QUICConfig.MaxIdleTimeout = 150 * time.Millisecond
	tr.QUICConfig.KeepAlivePeriod = 30 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q, err := tr.dial(ctx, "", tr.TLSClientConfig, tr.QUICConfig)
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(450 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-q.Context().Done():
		t.Fatal("keepalive failed to retain idle connection")
	case <-timer.C:
	}
}
