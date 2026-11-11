//go:build with_quic

package backend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

type h3HandlerDoneKey struct{}

type h3TrackedTarget struct {
	net.Conn
	closeCalls, halfCloses atomic.Int64
	closed, readStarted    chan struct{}
	handlerDone            chan struct{}
	closeOnce, readOnce    sync.Once
	failRead               <-chan struct{}
	failWrite              bool
}

func (c *h3TrackedTarget) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func (c *h3TrackedTarget) CloseWrite() error {
	c.halfCloses.Add(1)
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}
func (c *h3TrackedTarget) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	if c.failRead != nil {
		select {
		case <-c.failRead:
			return 0, errors.New("controlled target read failure")
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	return c.Conn.Read(p)
}
func (c *h3TrackedTarget) Write(p []byte) (int, error) {
	if c.failWrite {
		return 0, errors.New("controlled target write failure")
	}
	return c.Conn.Write(p)
}

type h3OwnershipTrace struct {
	body                   *bodyConn
	target                 *h3TrackedTarget
	ctx                    context.Context
	handlerDone, relayDone chan struct{}
	counter                *traffic.Counter
}

// The handler barrier is outside ServeHTTP: admission and its handler waitgroup
// have already been released when it closes. Relay and body barriers are separate.
func h3OwnershipServer(t *testing.T, limit int, failRead <-chan struct{}, failWrite bool) (string, *tls.Config, *Server, <-chan *h3OwnershipTrace) {
	t.Helper()
	settings := testkit.TLS(t)
	cert, err := tls.LoadX509KeyPair(settings.CertificateFile, settings.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(settings.CACertificate)) {
		t.Fatal("CA")
	}
	traces := make(chan *h3OwnershipTrace, 16)
	var targets sync.Map
	s, err := NewServer(ServerConfig{Mode: "quic", TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, MaxStreams: limit, IdleTimeout: time.Hour,
		Authenticate: func(u, p string) (string, bool) { return u, u == "alpha" && p == "alpha-pass" },
		Dial: func(ctx context.Context, _ string, target string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
			if err != nil {
				return nil, err
			}
			tracked := &h3TrackedTarget{Conn: conn, closed: make(chan struct{}), readStarted: make(chan struct{}), handlerDone: ctx.Value(h3HandlerDoneKey{}).(chan struct{}), failRead: failRead, failWrite: failWrite}
			targets.Store(conn.LocalAddr().String(), tracked)
			return tracked, nil
		},
		Relay: func(ctx context.Context, _ string, client, target net.Conn) {
			raw := client
			if padded, ok := raw.(*PaddingConn); ok {
				raw = padded.Conn
			}
			tracked, _ := targets.Load(target.LocalAddr().String())
			targets.Delete(target.LocalAddr().String())
			counter := &traffic.Counter{}
			counted := traffic.Conn(client, counter)
			trace := &h3OwnershipTrace{body: raw.(*bodyConn), target: tracked.(*h3TrackedTarget), ctx: ctx, handlerDone: tracked.(*h3TrackedTarget).handlerDone, relayDone: make(chan struct{}), counter: counter}
			traces <- trace
			defer close(trace.relayDone)
			defer counted.Close()
			relay.Join(ctx, counted, target)
		}})
	if err != nil {
		t.Fatal(err)
	}
	h3 := s.h3.(*h3Server)
	h3.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		done := make(chan struct{})
		defer close(done)
		s.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), h3HandlerDoneKey{}, done)))
	})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() { defer close(served); _ = s.ServeUDP(packet) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Close(ctx); err != nil {
			t.Error(err)
		}
		_ = packet.Close()
		halfCloseWait(t, served)
	})
	return packet.LocalAddr().String(), &tls.Config{ServerName: settings.ServerName, RootCAs: roots}, s, traces
}

func h3Trace(t *testing.T, traces <-chan *h3OwnershipTrace) *h3OwnershipTrace {
	t.Helper()
	select {
	case r := <-traces:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("relay not admitted")
		return nil
	}
}

// Expire only this stream under the production mutex, then arm its existing
// idle timer. The actual timer callback/terminate path runs;
// there is no extra timeout, direct terminate call, sleep or production clock hook.
func h3ExpireIdle(t *testing.T, c *bodyConn) {
	t.Helper()
	c.mu.Lock()
	closed, idle := c.closed, c.idle
	if closed || idle != time.Hour {
		c.mu.Unlock()
		t.Fatal("idle owner not live", closed, idle)
	}
	// Apply the expiry to the stream's idle interval. Padding that was already
	// in flight may still touch last after the target receives the payload;
	// changing only last would let that touch postpone the forced expiry by an
	// hour. The real timer and terminal ownership path still perform the close.
	c.idle = time.Nanosecond
	c.last = time.Now().Add(-c.idle)
	c.armIdleLocked()
	c.mu.Unlock()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		c.mu.Lock()
		last, idle, closed := c.last, c.idle, c.closed
		c.mu.Unlock()
		t.Fatalf("idle callback did not terminate: last=%s idle=%s closed=%t age=%s", last, idle, closed, time.Since(last))
	}
	t.Log("h3_idle existing_timer_fired=1 manually_advanced_activity_timestamp=1 extra_timer=0")
}

func h3AssertLive(t *testing.T, s *Server, r *h3OwnershipTrace, admissions int) {
	t.Helper()
	halfCloseWait(t, r.target.readStarted)
	if r.ctx.Err() != nil || r.target.closeCalls.Load() != 0 || r.counter.Snapshot().Active != 1 || len(s.capacity) != admissions {
		t.Fatal("normal EOF terminated ownership", r.ctx.Err(), r.target.closeCalls.Load(), r.counter.Snapshot(), len(s.capacity))
	}
	select {
	case <-r.handlerDone:
		t.Fatal("handler returned while opposite direction valid")
	default:
	}
}

func h3AssertReleased(t *testing.T, s *Server, r *h3OwnershipTrace, admissions int) {
	t.Helper()
	halfCloseWait(t, r.handlerDone)
	halfCloseWait(t, r.relayDone)
	halfCloseWait(t, r.body.done)
	halfCloseWait(t, r.body.pumpDone)
	halfCloseWait(t, r.target.closed)
	if r.target.closeCalls.Load() != 1 || r.counter.Snapshot().Active != 0 || len(s.capacity) != admissions {
		t.Fatal("ownership release", r.target.closeCalls.Load(), r.counter.Snapshot(), len(s.capacity))
	}
	r.body.mu.Lock()
	closed := r.body.closed
	timer := r.body.idleTimer
	r.body.mu.Unlock()
	if !closed || timer.Stop() {
		t.Fatal("idle timer retained")
	}
	t.Logf("h3_ownership target_close=1 relays_remaining=0 handlers_remaining=0 active_sessions=0 admissions_remaining=%d read_pumps_remaining=0 timers_remaining=0", admissions)
}

func h3AssertPoolEmpty(t *testing.T, c *Client) {
	t.Helper()
	joined := make(chan struct{})
	go func() { c.connecting.Wait(); c.watchers.Wait(); close(joined) }()
	halfCloseWait(t, joined)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.capacity) != 0 {
		t.Fatal("client stream reservation retained", len(c.capacity))
	}
	for _, slot := range c.slots {
		if slot != nil && (slot.active != 0 || len(slot.streams) != 0) {
			t.Fatal("client stream owner retained")
		}
	}
	t.Log("h3_client_owner streams_remaining=0 watchers_remaining=0 setup_workers_remaining=0")
}

func TestNaiveH3UploadEOFOwnership(t *testing.T) {
	for _, padding := range []string{"enabled", "off"} {
		for _, action := range []string{"delayed-response", "idle", "client-cancel", "connection-close", "server-shutdown", "target-hard-close", "cancel-idle-shutdown-race"} {
			t.Run(padding+"/"+action, func(t *testing.T) {
				up, down := halfClosePayload(65537), halfClosePayload(3<<20+65535)
				uploadEOF, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				target, received := halfCloseTarget(t, func(conn *net.TCPConn) error {
					got, err := io.ReadAll(conn)
					if err != nil || !bytes.Equal(got, up) {
						return fmt.Errorf("upload %d/%d: %v", len(got), len(up), err)
					}
					close(uploadEOF)
					<-release
					if action == "delayed-response" {
						if _, err := writeAll(conn, down); err != nil {
							return err
						}
						return conn.CloseWrite()
					}
					if action == "target-hard-close" {
						_ = conn.SetLinger(0)
					}
					return nil
				})
				t.Cleanup(unblock)
				proxy, tc, server, traces := h3OwnershipServer(t, 2, nil, false)
				client := newTestClient(t, "quic", proxy, tc, func(c *ClientConfig) { c.Padding = padding; c.IdleTimeout = time.Hour }, nil)
				conn, err := client.Open(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				trace := h3Trace(t, traces)
				if _, err := writeAll(conn, up); err != nil {
					t.Fatal(err)
				}
				if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				halfCloseWait(t, uploadEOF)
				halfCloseWait(t, trace.body.pumpDone)
				h3AssertLive(t, server, trace, 1)
				if trace.target.halfCloses.Load() != 1 {
					t.Fatal("target write half not closed")
				}
				read := make(chan error, 1)
				go func() {
					got, err := io.ReadAll(conn)
					if action == "delayed-response" && (err != nil || !bytes.Equal(got, down)) {
						err = fmt.Errorf("downlink %d/%d: %v", len(got), len(down), err)
					}
					_ = conn.Close()
					read <- err
				}()
				switch action {
				case "delayed-response", "target-hard-close":
					unblock()
				case "idle":
					h3ExpireIdle(t, trace.body)
				case "client-cancel":
					_ = conn.Close()
				case "connection-close":
					client.mu.Lock()
					owner := client.slots[0].conn
					client.mu.Unlock()
					_ = owner.close()
				case "server-shutdown":
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := server.Close(ctx); err != nil {
						t.Fatal(err)
					}
				case "cancel-idle-shutdown-race":
					var workers sync.WaitGroup
					workers.Add(2)
					gate := make(chan struct{})
					go func() { defer workers.Done(); <-gate; _ = conn.Close() }()
					go func() {
						defer workers.Done()
						<-gate
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						_ = server.Close(ctx)
					}()
					h3ExpireIdle(t, trace.body)
					close(gate)
					workers.Wait()
				}
				h3AssertReleased(t, server, trace, 0)
				if action == "delayed-response" {
					halfCloseResult(t, read)
				} else {
					select {
					case <-read:
					case <-time.After(5 * time.Second):
						t.Fatal("client read owner retained")
					}
				}
				h3AssertPoolEmpty(t, client)
				unblock()
				halfCloseResult(t, received)
				t.Logf("h3_upload_eof profile=%s padding=%s upload=%d upload_sha256=%x delayed_downlink=%d payload_integrity=PASS cleanup=PASS", action, padding, len(up), sha256.Sum256(up), len(down))
			})
		}
	}
}

func TestNaiveH3IdleAdmissionMultiplexReuse(t *testing.T) {
	for _, padding := range []string{"enabled", "off"} {
		for _, terminal := range []string{"idle", "client-cancel", "connection-close", "server-shutdown"} {
			t.Run(padding+"/"+terminal, func(t *testing.T) {
				up := halfClosePayload(65536)
				uploadEOF, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				target, received := halfCloseTarget(t, func(c *net.TCPConn) error {
					got, err := io.ReadAll(c)
					if err != nil || !bytes.Equal(got, up) {
						return fmt.Errorf("upload integrity: %v", err)
					}
					close(uploadEOF)
					<-release
					return nil
				})
				t.Cleanup(unblock)
				proxy, tc, server, traces := h3OwnershipServer(t, 2, nil, false)
				var dials atomic.Int64
				client := newTestClient(t, "quic", proxy, tc, func(c *ClientConfig) { c.Padding = padding; c.IdleTimeout = time.Hour }, &dials)
				a, err := client.Open(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				ra := h3Trace(t, traces)
				_, _ = writeAll(a, up)
				if err := a.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				halfCloseWait(t, uploadEOF)
				bTarget := echoTarget(t, "tcp", "127.0.0.1:0")
				b, err := client.Open(context.Background(), bTarget)
				if err != nil {
					t.Fatal(err)
				}
				defer b.Close()
				rb := h3Trace(t, traces)
				echo := func() {
					data := halfClosePayload(32768)
					write := make(chan error, 1)
					go func() { _, err := writeAll(b, data); write <- err }()
					got := make([]byte, len(data))
					if _, err := io.ReadFull(b, got); err != nil || !bytes.Equal(got, data) {
						t.Fatal("healthy sibling", err)
					}
					halfCloseResult(t, write)
				}
				echo()
				h3AssertLive(t, server, ra, 2)
				rejected := newTestClient(t, "quic", proxy, tc, nil, nil)
				if conn, err := rejected.Open(context.Background(), bTarget); err == nil {
					conn.Close()
					t.Fatal("global admission limit bypassed")
				}
				if terminal == "connection-close" || terminal == "server-shutdown" {
					if terminal == "connection-close" {
						client.mu.Lock()
						owner := client.slots[0].conn
						client.mu.Unlock()
						_ = owner.close()
					} else {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						if err := server.Close(ctx); err != nil {
							t.Fatal(err)
						}
					}
					halfCloseWait(t, ra.handlerDone)
					halfCloseWait(t, rb.handlerDone)
					h3AssertReleased(t, server, ra, 0)
					h3AssertReleased(t, server, rb, 0)
					_ = a.Close()
					_ = b.Close()
					h3AssertPoolEmpty(t, client)
					unblock()
					halfCloseResult(t, received)
					t.Logf("h3_children terminal=%s child_tunnels=2 targets_closed=2 admissions_remaining=0 cleanup=PASS", terminal)
					return
				}
				if terminal == "idle" {
					h3ExpireIdle(t, ra.body)
				} else {
					_ = a.Close()
				}
				h3AssertReleased(t, server, ra, 1)
				_ = a.Close()
				echo()
				h3AssertLive(t, server, rb, 1)
				transfer(t, client, bTarget, 65537)
				rc := h3Trace(t, traces)
				h3AssertReleased(t, server, rc, 1)
				if dials.Load() != 1 {
					t.Fatal("idle stream poisoned carrier", dials.Load())
				}
				_ = b.Close()
				h3AssertReleased(t, server, rb, 0)
				h3AssertPoolEmpty(t, client)
				unblock()
				halfCloseResult(t, received)
				t.Logf("h3_multiplex terminal=%s admission_limit=2 admission_reclaimed=1 sibling_integrity=PASS replacement_stream=PASS carrier_dials=1 cleanup=PASS", terminal)
			})
		}
	}
}

func TestNaiveH3ActiveAndTargetFailureCleanup(t *testing.T) {
	for _, padding := range []string{"enabled", "off"} {
		for _, action := range []string{"idle-active", "reset-active", "target-read-error", "target-write-error"} {
			t.Run(padding+"/"+action, func(t *testing.T) {
				up := halfClosePayload(4096)
				uploadRead := make(chan struct{})
				target, result := halfCloseTarget(t, func(c *net.TCPConn) error {
					if action != "target-write-error" {
						got := make([]byte, len(up))
						if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, up) {
							return fmt.Errorf("active upload integrity: %v", err)
						}
						close(uploadRead)
					}
					_, err := io.Copy(io.Discard, c)
					if e, ok := err.(net.Error); ok && e.Timeout() {
						return err
					}
					return nil
				})
				var failRead chan struct{}
				if action == "target-read-error" {
					failRead = make(chan struct{})
				}
				proxy, tc, server, traces := h3OwnershipServer(t, 2, failRead, action == "target-write-error")
				client := newTestClient(t, "quic", proxy, tc, func(c *ClientConfig) { c.Padding = padding; c.IdleTimeout = time.Hour }, nil)
				conn, err := client.Open(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				trace := h3Trace(t, traces)
				if _, err := writeAll(conn, up); err != nil && action != "target-write-error" {
					t.Fatal(err)
				}
				if action != "target-write-error" {
					halfCloseWait(t, uploadRead)
					h3AssertLive(t, server, trace, 1)
				}
				switch action {
				case "idle-active":
					h3ExpireIdle(t, trace.body)
				case "reset-active":
					_ = conn.Close()
				case "target-read-error":
					if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					close(failRead)
				}
				h3AssertReleased(t, server, trace, 0)
				_ = conn.Close()
				h3AssertPoolEmpty(t, client)
				halfCloseResult(t, result)
				t.Logf("h3_failure profile=%s padding=%s cleanup=PASS", action, padding)
			})
		}
	}
}

func TestNaiveH3RejectedBeforeTargetOwnership(t *testing.T) {
	proxy, tc, server, traces := h3OwnershipServer(t, 1, nil, false)
	target := echoTarget(t, "tcp", "127.0.0.1:0")
	for _, action := range []string{"wrong-auth", "dial-failure"} {
		t.Run(action, func(t *testing.T) {
			cfg := func(c *ClientConfig) {
				if action == "wrong-auth" {
					c.Password = "wrong"
				}
			}
			client := newTestClient(t, "quic", proxy, tc, cfg, nil)
			address := target
			if action == "dial-failure" {
				address = "127.0.0.1:0"
			}
			if conn, err := client.Open(context.Background(), address); err == nil {
				conn.Close()
				t.Fatal("rejected path succeeded")
			}
			joined := make(chan struct{})
			go func() { server.handlers.Wait(); close(joined) }()
			halfCloseWait(t, joined)
			if len(server.capacity) != 0 || len(traces) != 0 {
				t.Fatal("rejected path retained admission/relay")
			}
			h3AssertPoolEmpty(t, client)
		})
	}
	client := newTestClient(t, "quic", proxy, tc, nil, nil)
	transfer(t, client, target, 65536)
	h3AssertReleased(t, server, h3Trace(t, traces), 0)
}
