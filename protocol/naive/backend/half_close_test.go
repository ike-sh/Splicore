package backend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// All ordering gates are explicit. Deadlines below only bound a broken test.
func halfCloseWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("half-close lifecycle did not reach the required state")
	}
}

func halfCloseResult(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		var dump bytes.Buffer
		_ = pprof.Lookup("goroutine").WriteTo(&dump, 2)
		t.Fatalf("half-close worker did not join; goroutines:\n%s", dump.String())
	}
}

func halfClosePayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte((i*31 + i/251) % 256)
	}
	return p
}

// The upload copy has started before the response is allowed, and cannot
// consume its tail until the test observes the server's sending half-close.
type halfCloseGatedReader struct {
	prefix, tail *bytes.Reader
	pending      chan struct{}
	release      <-chan struct{}
	once         sync.Once
}

func (r *halfCloseGatedReader) Read(p []byte) (int, error) {
	if r.prefix.Len() > 0 {
		return r.prefix.Read(p)
	}
	r.once.Do(func() { close(r.pending) })
	<-r.release
	return r.tail.Read(p)
}

func halfCloseTarget(t *testing.T, serve func(*net.TCPConn) error) (string, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	done := make(chan struct{})
	var mu sync.Mutex
	var owned net.Conn
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			result <- err
			return
		}
		mu.Lock()
		owned = conn
		mu.Unlock()
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		result <- serve(conn.(*net.TCPConn))
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		if owned != nil {
			_ = owned.Close()
		}
		mu.Unlock()
		halfCloseWait(t, done)
	})
	return l.Addr().String(), result
}

type halfCloseObservedConn struct {
	net.Conn
	once sync.Once
	eof  chan struct{}
}

func (c *halfCloseObservedConn) CloseWrite() error {
	err := c.Conn.(interface{ CloseWrite() error }).CloseWrite()
	if err == nil {
		c.once.Do(func() { close(c.eof) })
	}
	return err
}

func halfCloseServer(t *testing.T, mode, observedTarget string, eof, joined chan struct{}, configure ...func(*ServerConfig)) (string, *ClientConfig, *Server) {
	t.Helper()
	proxy, tc, server := startTestServerConfigured(t, mode, func(c *ServerConfig) {
		original := c.Relay
		c.Relay = func(ctx context.Context, user string, client, target net.Conn) {
			if target.RemoteAddr().String() == observedTarget {
				client = &halfCloseObservedConn{Conn: client, eof: eof}
				defer close(joined)
			}
			original(ctx, user, client, target)
		}
		for _, apply := range configure {
			apply(c)
		}
	})
	return proxy, &ClientConfig{TLS: tc}, server
}

func TestNaiveDirectionalHalfClose(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		for _, padding := range []string{"enabled", "off"} {
			for _, profile := range []string{"target-response-first", "target-immediate-EOF", "concurrent-large-upload", "multiplex"} {
				t.Run(mode+"/"+padding+"/"+profile, func(t *testing.T) {
					if mode == "quic" && !H3Enabled() {
						t.Skip("with_quic required")
					}
					payload := halfClosePayload(3<<20 + 65537)
					response := []byte("early independent target response")
					prefix := 0
					if profile != "target-immediate-EOF" {
						prefix = 4096
					}
					eof, joined := make(chan struct{}), make(chan struct{})
					pending, release := make(chan struct{}), make(chan struct{})
					var releaseOnce sync.Once
					unblock := func() { releaseOnce.Do(func() { close(release) }) }
					target, received := halfCloseTarget(t, func(conn *net.TCPConn) error {
						data := make([]byte, prefix)
						if _, err := io.ReadFull(conn, data); err != nil {
							return err
						}
						if profile == "concurrent-large-upload" {
							<-pending
						}
						if _, err := conn.Write(response); err != nil {
							return err
						}
						if err := conn.CloseWrite(); err != nil {
							return err
						}
						tail, err := io.ReadAll(conn)
						if err != nil {
							return err
						}
						data = append(data, tail...)
						if !bytes.Equal(data, payload) {
							return fmt.Errorf("upload integrity: expected %d bytes, received %d", len(payload), len(data))
						}
						return nil
					})
					proxy, config, _ := halfCloseServer(t, mode, target, eof, joined)
					var count atomic.Int64
					client := newTestClient(t, mode, proxy, config.TLS, func(c *ClientConfig) { c.Padding = padding }, &count)
					conn, err := client.Open(context.Background(), target)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					defer unblock()
					_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
					write := make(chan error, 1)
					if profile == "concurrent-large-upload" {
						go func() {
							_, err := io.Copy(conn, &halfCloseGatedReader{prefix: bytes.NewReader(payload[:prefix]), tail: bytes.NewReader(payload[prefix:]), pending: pending, release: release})
							if err == nil {
								err = conn.(interface{ CloseWrite() error }).CloseWrite()
							}
							write <- err
						}()
					} else if _, err := conn.Write(payload[:prefix]); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(response))
					if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, response) {
						t.Fatal("early downlink lost", err)
					}
					// This is the server relay's actual successful CloseWrite, not
					// merely the target's intent. The remaining >3MiB upload has
					// not been submitted at this barrier.
					halfCloseWait(t, eof)
					select {
					case <-joined:
						t.Fatal("relay completed before remaining upload")
					default:
					}
					if profile == "multiplex" {
						transfer(t, client, echoTarget(t, "tcp", "127.0.0.1:0"), 65536)
					}
					// H3 sends its directional FIN immediately. H2's standard
					// ResponseWriter sends END_STREAM at handler return after
					// both directions join, while flushed bytes arrive above.
					if mode == "quic" {
						var b [1]byte
						if n, err := conn.Read(b[:]); n != 0 || err != io.EOF {
							t.Fatal("H3 downlink FIN", n, err)
						}
					}
					if profile == "concurrent-large-upload" {
						unblock()
					} else {
						go func() {
							_, err := writeAll(conn, payload[prefix:])
							if err == nil {
								err = conn.(interface{ CloseWrite() error }).CloseWrite()
							}
							write <- err
						}()
					}
					if tail, err := io.ReadAll(conn); err != nil || len(tail) != 0 {
						t.Fatal("downlink completion", len(tail), err)
					}
					halfCloseResult(t, write)
					halfCloseResult(t, received)
					halfCloseWait(t, joined)
					conn.Close()
					transfer(t, client, echoTarget(t, "tcp", "127.0.0.1:0"), 65537)
					if count.Load() != 1 {
						t.Fatal("directional EOF killed shared connection", count.Load())
					}
					t.Logf("target downlink EOF before remaining upload; expected=%d actual=%d mismatch=0 truncation=0 duplication=0 ordering_error=0 upload_sha256=%x response_bytes=%d", len(payload), len(payload), sha256.Sum256(payload), len(response))
				})
			}
		}
	}
}

func TestNaiveClientFirstHalfClose(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		for _, padding := range []string{"enabled", "off"} {
			t.Run(mode+"/"+padding, func(t *testing.T) {
				if mode == "quic" && !H3Enabled() {
					t.Skip("with_quic required")
				}
				up, down := halfClosePayload(65536), halfClosePayload(3<<20+65535)
				target, result := halfCloseTarget(t, func(conn *net.TCPConn) error {
					got, err := io.ReadAll(conn)
					if err != nil || !bytes.Equal(got, up) {
						return fmt.Errorf("client-first upload: %d/%d: %v", len(got), len(up), err)
					}
					// Target observed actual upload EOF before starting downlink.
					if _, err := writeAll(conn, down); err != nil {
						return err
					}
					return conn.CloseWrite()
				})
				proxy, tc, _ := startTestServer(t, mode)
				client := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.Padding = padding }, nil)
				conn, err := client.Open(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := writeAll(conn, up); err != nil {
					t.Fatal(err)
				}
				if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(conn)
				if err != nil || !bytes.Equal(got, down) {
					t.Fatal("continued downlink integrity", len(got), err)
				}
				halfCloseResult(t, result)
				t.Logf("upload EOF precedes downlink; upload=%d download=%d mismatch=0", len(up), len(down))
			})
		}
	}
}

func TestNaiveHalfCloseFatalLifecycle(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		for _, action := range []string{"target-hard-close", "client-stream-reset", "reset-after-downlink-EOF", "server-shutdown", "malformed-padding", "idle-after-downlink-EOF"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				if mode == "quic" && !H3Enabled() {
					t.Skip("with_quic required")
				}
				active := make(chan struct{})
				release := make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				target, result := halfCloseTarget(t, func(conn *net.TCPConn) error {
					var b [1]byte
					if _, err := io.ReadFull(conn, b[:]); err != nil {
						return err
					}
					close(active)
					if action == "reset-after-downlink-EOF" || action == "idle-after-downlink-EOF" {
						if err := conn.CloseWrite(); err != nil {
							return err
						}
					}
					if action == "target-hard-close" {
						<-release
						_ = conn.SetLinger(0)
						return conn.Close()
					}
					_, err := io.Copy(io.Discard, conn)
					// Cancellation can be represented as TCP EOF or reset.
					if err != nil {
						if e, ok := err.(net.Error); ok && e.Timeout() {
							return err
						}
					}
					return nil
				})
				t.Cleanup(unblock)
				eof, joined := make(chan struct{}), make(chan struct{})
				proxy, config, server := halfCloseServer(t, mode, target, eof, joined, func(c *ServerConfig) {
					if action == "idle-after-downlink-EOF" {
						c.IdleTimeout = 100 * time.Millisecond
					}
				})
				client := newTestClient(t, mode, proxy, config.TLS, nil, nil)
				conn, err := client.Open(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := conn.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
				halfCloseWait(t, active)
				if action == "reset-after-downlink-EOF" || action == "idle-after-downlink-EOF" {
					halfCloseWait(t, eof)
				}
				read := make(chan error, 1)
				go func() { var b [1]byte; _, err := conn.Read(b[:]); read <- err }()
				switch action {
				case "target-hard-close":
					unblock()
				case "client-stream-reset", "reset-after-downlink-EOF":
					_ = conn.Close()
				case "malformed-padding":
					// Start an incomplete next padding frame, then end upload.
					raw := conn.(*pooledStream).raw
					if _, err := raw.Write([]byte{0xff}); err != nil {
						t.Fatal(err)
					}
					if err := raw.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
				case "server-shutdown":
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := server.Close(ctx); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case err := <-read:
					if err == nil {
						t.Fatal("fatal lifecycle did not interrupt stream")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("fatal read did not join")
				}
				halfCloseWait(t, joined)
				halfCloseResult(t, result)
			})
		}
	}
}
