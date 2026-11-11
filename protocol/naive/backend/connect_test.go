package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startTestServer(t *testing.T, mode string) (string, *tls.Config, *Server) {
	return startTestServerConfigured(t, mode, nil)
}
func startTestServerConfigured(t *testing.T, mode string, configure func(*ServerConfig)) (string, *tls.Config, *Server) {
	t.Helper()
	settings := testkit.TLS(t)
	cert, _ := os.ReadFile(settings.CertificateFile)
	key, _ := os.ReadFile(settings.PrivateKeyFile)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(settings.CACertificate))
	tc := &tls.Config{ServerName: settings.ServerName, RootCAs: pool, MinVersion: tls.VersionTLS12}
	config := ServerConfig{Mode: mode, TLS: &tls.Config{Certificates: []tls.Certificate{pair}},
		Authenticate: func(u, p string) (string, bool) {
			return u, (u == "alpha" && p == "alpha-pass") || (u == "beta" && p == "beta-pass")
		},
		Dial: func(ctx context.Context, _ string, target string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", target)
		},
		Relay: func(ctx context.Context, _ string, a, b net.Conn) { relay.Join(ctx, a, b) }}
	if configure != nil {
		configure(&config)
	}
	s, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	var address string
	done := make(chan struct{})
	if mode == "quic" {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address = packet.LocalAddr().String()
		go func() { defer close(done); _ = s.ServeUDP(packet) }()
		t.Cleanup(func() { _ = packet.Close() })
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address = listener.Addr().String()
		go func() { defer close(done); _ = s.ServeTCP(listener) }()
		t.Cleanup(func() { _ = listener.Close() })
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Close(ctx); err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-ctx.Done():
			t.Error("server worker leak")
		}
	})
	return address, tc, s
}
func newTestClient(t *testing.T, mode, proxy string, tc *tls.Config, config func(*ClientConfig), dialCount *atomic.Int64) *Client {
	t.Helper()
	cfg := ClientConfig{Mode: mode, Proxy: proxy, Username: "alpha", Password: "alpha-pass", TLS: tc,
		DialTCP: func(ctx context.Context, network, address string) (net.Conn, error) {
			if dialCount != nil {
				dialCount.Add(1)
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
		PacketSocket: func(context.Context) (net.PacketConn, net.Addr, error) {
			if dialCount != nil {
				dialCount.Add(1)
			}
			remote, err := net.ResolveUDPAddr("udp", proxy)
			if err != nil {
				return nil, nil, err
			}
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			return packet, remote, err
		}}
	if config != nil {
		config(&cfg)
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
func echoTarget(t *testing.T, network, address string) string {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() { defer workers.Done(); defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; workers.Wait() })
	return listener.Addr().String()
}
func transfer(t *testing.T, client *Client, target string, size int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.Open(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte{byte(size), 0xa7, 0x31}, (size+2)/3)[:size]
	write := make(chan error, 1)
	go func() {
		_, err := writeAll(conn, payload)
		if err == nil {
			err = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		write <- err
	}()
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload integrity %d/%d: %v", len(got), len(payload), err)
	}
	if err := <-write; err != nil {
		t.Fatal(err)
	}
}
func TestNaiveCONNECTH2H3PayloadDestinationsAndPaddingNegotiation(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, _ := startTestServer(t, mode)
			target := echoTarget(t, "tcp", "127.0.0.1:0")
			client := newTestClient(t, mode, proxy, tc, nil, nil)
			for _, size := range []int{1, 19, 65535, 65536, 65537, 3 << 20} {
				t.Run(strconv.Itoa(size), func(t *testing.T) { transfer(t, client, target, size) })
			}
			host, port, _ := net.SplitHostPort(target)
			_ = host
			t.Run("domain", func(t *testing.T) { transfer(t, client, net.JoinHostPort("localhost", port), 1234) })
			t.Run("raw-no-padding", func(t *testing.T) {
				raw := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.Padding = "off" }, nil)
				transfer(t, raw, target, 65536)
			})
			t.Run("ipv6", func(t *testing.T) {
				probe, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skip("local IPv6 unavailable")
				}
				_ = probe.Close()
				ipv6 := echoTarget(t, "tcp6", "[::1]:0")
				transfer(t, client, ipv6, 12000)
			})
		})
	}
}
func TestNaiveCONNECTMultiplexAndStreamIsolation(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, _ := startTestServer(t, mode)
			target := echoTarget(t, "tcp", "127.0.0.1:0")
			var count atomic.Int64
			client := newTestClient(t, mode, proxy, tc, nil, &count)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			streams := make([]net.Conn, 12)
			for i := range streams {
				conn, err := client.Open(ctx, target)
				if err != nil {
					t.Fatal(err)
				}
				streams[i] = conn
			}
			_ = streams[0].Close()
			var workers sync.WaitGroup
			errorsCh := make(chan error, len(streams))
			for i, conn := range streams[1:] {
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte{byte(i)}, 100000+i)
					write := make(chan error, 1)
					go func() { _, err := writeAll(conn, payload); write <- err }()
					got := make([]byte, len(payload))
					_, err := io.ReadFull(conn, got)
					if err == nil && !bytes.Equal(got, payload) {
						err = errors.New("cross-stream data")
					}
					if writeErr := <-write; err == nil {
						err = writeErr
					}
					errorsCh <- err
				}()
			}
			workers.Wait()
			close(errorsCh)
			for err := range errorsCh {
				if err != nil {
					t.Fatal(err)
				}
			}
			if count.Load() != 1 {
				t.Fatalf("expected one reused connection, got %d", count.Load())
			}
		})
	}
}
func TestNaiveAuthenticationMultiUserAndPreamble(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, s := startTestServer(t, mode)
			target := echoTarget(t, "tcp", "127.0.0.1:0")
			for _, user := range []struct {
				name, password string
				valid          bool
			}{{"alpha", "alpha-pass", true}, {"beta", "beta-pass", true}, {"alpha", "beta-pass", false}, {"unknown", "alpha-pass", false}} {
				t.Run(user.name+"/"+strconv.Itoa(len(user.password)), func(t *testing.T) {
					client := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.Username = user.name; c.Password = user.password }, nil)
					if user.valid {
						transfer(t, client, target, 321)
					} else {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						if conn, err := client.Open(ctx, target); err == nil {
							_ = conn.Close()
							t.Fatal("invalid credential accepted")
						}
					}
				})
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				req, _ := http.NewRequest(method, "https://local/", nil)
				writer := &recordingWriter{header: http.Header{}}
				s.ServeHTTP(writer, req)
				if writer.code != 200 {
					t.Fatal("preamble not tolerated")
				}
				if method == http.MethodHead && writer.body.Len() != 0 {
					t.Fatal("HEAD payload")
				}
			}
		})
	}
}

type recordingWriter struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (w *recordingWriter) Header() http.Header         { return w.header }
func (w *recordingWriter) WriteHeader(code int)        { w.code = code }
func (w *recordingWriter) Write(p []byte) (int, error) { return w.body.Write(p) }

func TestNaiveReadDeadlineResetPreservesBytesAndWriteTimeout(t *testing.T) {
	read, send := io.Pipe()
	output := &bytes.Buffer{}
	conn := newBodyConn(read, output, func() error { return nil }, func(bool) { _ = read.Close() }, streamAddr("a"), streamAddr("b"), time.Hour)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	var b [1]byte
	if _, err := conn.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	go func() { _, _ = send.Write([]byte{9}); _ = send.Close() }()
	if _, err := io.ReadFull(conn, b[:]); err != nil || b[0] != 9 {
		t.Fatal(b, err)
	}
	t.Run("write", func(t *testing.T) {
		pr, pw := io.Pipe()
		blockedRead, unblockRead := io.Pipe()
		c := newBodyConn(blockedRead, pw, pw.Close, func(bool) { _ = pr.Close(); _ = unblockRead.Close() }, streamAddr("a"), streamAddr("b"), time.Hour)
		defer c.Close()
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
		if _, err := c.Write([]byte("blocked")); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	})
}

func TestNaiveExtraHeaderValidation(t *testing.T) {
	if ValidateHeaders(http.Header{"X-Client": []string{"native"}}) != nil {
		t.Fatal("valid header rejected")
	}
	for _, headers := range []http.Header{{"Padding": []string{"x"}}, {"pAdDiNg": []string{"x"}}, {"Proxy-Authorization": []string{"x"}}, {"Host": []string{"x"}}, {"Fastopen": []string{"1"}}, {"bad:name": []string{"x"}}, {"X-Test": []string{"a\r\nb"}}, {"X-Test": []string{"a"}, "x-test": []string{"b"}}, {"X-Test": []string{string(make([]byte, 9000))}}} {
		if ValidateHeaders(headers) == nil {
			t.Fatal("invalid header accepted")
		}
	}
}
