package backend

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	api "github.com/enfein/mieru/v3/apis/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/mieru"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

// Use the real outbound and SDK with a controlled TCP target. Payloads are at
// most two bytes, including with a UDP underlay; no large-datagram path is used.
func mieruDeadlinePair(t *testing.T, transport string, handshake bool) (net.Conn, net.Conn) {
	t.Helper()
	in := mieruIntent(t, transport)
	startMieru(t, in)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	id, _ := identity.NewID()
	cid, _ := identity.NewID()
	options, _ := json.Marshal(module.Settings{Transport: transport, MTU: 1500, Multiplex: "default"})
	node := client.RemoteNode{ID: id, Name: "deadline", Protocol: module.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cid, Transport: client.Transport{Kind: transport}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: options}}
	credential := in.Credentials[0]
	credential.ID, credential.OwnerAccountID, credential.OwnerNodeID = cid, nil, &id
	dialer, err := (MieruOutboundFactory{}).Build(underlay.WithFactory(context.Background(), underlay.New()), node, credential)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dialer.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, access.Endpoint{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if conn.LocalAddr().Network() == "pipe" || conn.RemoteAddr().Network() == "pipe" {
		t.Fatal("read adapter hid SDK socket addresses")
	}
	if !handshake {
		return conn, nil
	}
	if _, err = conn.Write(nil); err != nil {
		t.Fatal(err)
	}
	listener.SetDeadline(time.Now().Add(2 * time.Second))
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	return conn, peer
}

func mieruWantTimeout(t *testing.T, err error) {
	t.Helper()
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("want deadline timeout, got %v", err)
	}
}

func TestMieruReadDeadlineContract(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			t.Run("initial-before-handshake", func(t *testing.T) {
				conn, _ := mieruDeadlinePair(t, transport, false)
				watchdog := time.AfterFunc(time.Second, func() { conn.Close() })
				defer watchdog.Stop()
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				_, err := conn.Read(make([]byte, 1))
				mieruWantTimeout(t, err)
			})
			t.Run("readfull-persists-after-partial-read", func(t *testing.T) {
				conn, peer := mieruDeadlinePair(t, transport, true)
				watchdog := time.AfterFunc(time.Second, func() { conn.Close() })
				defer watchdog.Stop()
				conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
				if _, err := peer.Write([]byte("a")); err != nil {
					t.Fatal(err)
				}
				n, err := io.ReadFull(conn, make([]byte, 2))
				if n != 1 {
					t.Fatalf("partial ReadFull = %d, want 1", n)
				}
				mieruWantTimeout(t, err)
				// A timeout must not kill the session; explicitly refresh it.
				conn.SetReadDeadline(time.Now().Add(time.Second))
				peer.Write([]byte("b"))
				if _, err = io.ReadFull(conn, make([]byte, 1)); err != nil {
					t.Fatal("connection not reusable after timeout", err)
				}
			})
			t.Run("write-does-not-extend-read-deadline", func(t *testing.T) {
				conn, peer := mieruDeadlinePair(t, transport, true)
				watchdog := time.AfterFunc(time.Second, func() { conn.Close() })
				defer watchdog.Stop()
				conn.SetDeadline(time.Now().Add(150 * time.Millisecond))
				if _, err := conn.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
				_, err := conn.Read(make([]byte, 1))
				mieruWantTimeout(t, err)
			})
			t.Run("expired-deadline-persists", func(t *testing.T) {
				conn, _ := mieruDeadlinePair(t, transport, true)
				watchdog := time.AfterFunc(time.Second, func() { conn.Close() })
				defer watchdog.Stop()
				conn.SetReadDeadline(time.Now().Add(-time.Second))
				for range 2 {
					_, err := conn.Read(make([]byte, 1))
					mieruWantTimeout(t, err)
				}
			})
			for _, clear := range []bool{false, true} {
				name := "extend-pending-read"
				if clear {
					name = "clear-pending-read"
				}
				t.Run(name, func(t *testing.T) {
					conn, peer := mieruDeadlinePair(t, transport, true)
					old := time.Now().Add(300 * time.Millisecond)
					conn.SetReadDeadline(old)
					result := make(chan error, 1)
					go func() { _, err := io.ReadFull(conn, make([]byte, 1)); result <- err }()
					// Change the deadline while the read waits, then deliver data
					// after its original deadline. This must remain the same read.
					time.Sleep(75 * time.Millisecond)
					next := time.Now().Add(time.Second)
					if clear {
						next = time.Time{}
					}
					if err := conn.SetReadDeadline(next); err != nil {
						t.Fatal(err)
					}
					time.Sleep(time.Until(old.Add(100 * time.Millisecond)))
					select {
					case err := <-result:
						t.Fatal("read used stale deadline", err)
					default:
					}
					if _, err := peer.Write([]byte("a")); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-result:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(time.Second):
						t.Fatal("updated read did not complete")
					}
				})
			}
			t.Run("shorten-pending-read", func(t *testing.T) {
				conn, _ := mieruDeadlinePair(t, transport, true)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				result := make(chan error, 1)
				go func() { _, err := conn.Read(make([]byte, 1)); result <- err }()
				time.Sleep(75 * time.Millisecond)
				conn.SetReadDeadline(time.Now().Add(-time.Second))
				select {
				case err := <-result:
					mieruWantTimeout(t, err)
				case <-time.After(time.Second):
					t.Fatal("pending read ignored shortened deadline")
				}
			})
			t.Run("concurrent-write-and-independent-write-deadline", func(t *testing.T) {
				conn, peer := mieruDeadlinePair(t, transport, true)
				conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
				result := make(chan error, 1)
				go func() { _, err := conn.Read(make([]byte, 1)); result <- err }()
				conn.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := conn.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-result:
					mieruWantTimeout(t, err)
				case <-time.After(time.Second):
					t.Fatal("write changed pending read deadline")
				}
			})
			for _, handshake := range []bool{false, true} {
				name := "close-before-handshake"
				if handshake {
					name = "close-pending-read"
				}
				t.Run(name, func(t *testing.T) {
					conn, _ := mieruDeadlinePair(t, transport, handshake)
					result := make(chan error, 1)
					go func() { _, err := conn.Read(make([]byte, 1)); result <- err }()
					closed := make(chan error, 1)
					go func() { closed <- conn.Close() }()
					select {
					case <-closed:
					case <-time.After(2 * time.Second):
						t.Fatal("Close did not join reader")
					}
					select {
					case err := <-result:
						if err == nil {
							t.Fatal("closed connection read succeeded")
						}
					case <-time.After(time.Second):
						t.Fatal("Close left blocked Read")
					}
					if err := conn.SetReadDeadline(time.Now()); err == nil {
						t.Fatal("closed connection accepted read deadline")
					}
					conn.Close()
				})
			}
			t.Run("dial-context-does-not-own-connected-stream", func(t *testing.T) {
				// mieruDeadlinePair cancels its dial context before returning.
				conn, peer := mieruDeadlinePair(t, transport, true)
				conn.SetReadDeadline(time.Now().Add(time.Second))
				peer.Write([]byte("a"))
				if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
					t.Fatal("dial context cancellation killed established stream", err)
				}
			})
		})
	}
}

type mieruCanceledDial struct {
	entered chan struct{}
	once    sync.Once
}

func (d *mieruCanceledDial) wait(ctx context.Context) error {
	d.once.Do(func() { close(d.entered) })
	<-ctx.Done()
	return ctx.Err()
}
func (d *mieruCanceledDial) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return nil, d.wait(ctx)
}
func (d *mieruCanceledDial) ListenPacket(ctx context.Context, _, _, _ string) (net.PacketConn, error) {
	return nil, d.wait(ctx)
}

func TestMieruSDKDialCancellation(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			in := mieruIntent(t, transport)
			template := mieruClient(t, in, 0)
			config, err := template.Load()
			if err != nil {
				t.Fatal(err)
			}
			copyConfig := *config
			gate := &mieruCanceledDial{entered: make(chan struct{})}
			copyConfig.Dialer, copyConfig.PacketDialer = gate, gate
			c := api.NewClient()
			if err = c.Store(&copyConfig); err != nil {
				t.Fatal(err)
			}
			if err = c.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Stop() })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				conn, err := c.DialContext(ctx, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
				if conn != nil {
					conn.Close()
				}
				result <- err
			}()
			select {
			case <-gate.entered:
			case <-time.After(time.Second):
				t.Fatal("SDK did not pass dial context to underlay")
			}
			cancel()
			select {
			case err := <-result:
				// SDK newUnderlay wraps these errors with %v, not %w. Its
				// contract is prompt cancellation, not errors.Is identity.
				if err == nil {
					t.Fatal("canceled SDK dial succeeded")
				}
				t.Logf("SDK cancellation error=%v; errors.Is(context.Canceled)=%t", err, errors.Is(err, context.Canceled))
			case <-time.After(time.Second):
				t.Fatal("canceled SDK dial did not return")
			}
		})
	}
}

func TestMieruReadConnBufferOwnershipAndJoin(t *testing.T) {
	a, b := net.Pipe()
	c := newMieruReadConn(a)
	t.Cleanup(func() { b.Close(); c.Close() })
	sent := make(chan error, 1)
	go func() { _, err := b.Write([]byte("safe")); sent <- err }()
	c.SetReadDeadline(time.Now().Add(-time.Second))
	buffer := []byte("keep")
	if _, err := c.Read(buffer); err == nil {
		t.Fatal("expired read succeeded")
	}
	if _, err := c.Read(nil); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "keep" {
		t.Fatal("SDK used expired caller buffer")
	}
	c.SetReadDeadline(time.Time{})
	if _, err := io.ReadFull(c, buffer); err != nil || string(buffer) != "safe" {
		t.Fatal("pending data lost after deadline reset", string(buffer), err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
	default:
		t.Fatal("Close did not join SDK reader")
	}
}
