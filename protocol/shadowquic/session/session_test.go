//go:build with_quic

package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	quic "github.com/metacubex/jls-quic-go"
	tls "github.com/metacubex/jls-tls"
)

const (
	testUser     = "phase30-synthetic-user-32-bytes-00"
	testPassword = "phase30-synthetic-pass-32-bytes-00"
	testName     = "camouflage.test"
)

func testSocket(remote net.Addr) func(context.Context) (net.PacketConn, net.Addr, error) {
	return func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, e := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
		return p, remote, e
	}
}

func testServer(t *testing.T, limits Limits) (*Server, net.Addr, *atomic.Int32) {
	t.Helper()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	calls := &atomic.Int32{}
	s, e := NewServer(context.Background(), p, ServerConfig{ServerName: testName, Camouflage: "127.0.0.1:9", Limits: limits, Users: []User{{ID: "binding", Username: testUser, Password: testPassword}}, Authorize: func(id string) bool { return id == "binding" }, PacketDialer: func(ctx context.Context, _, _ string) (net.PacketConn, net.Addr, error) {
		return testSocket(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})(ctx)
	}, TCP: func(ctx context.Context, id string, c net.Conn, dst access.Endpoint) error {
		calls.Add(1)
		_, e := io.Copy(c, c)
		if w, ok := c.(interface{ CloseWrite() error }); ok {
			_ = w.CloseWrite()
		}
		return e
	}, UDP: func(ctx context.Context, id string, p net.PacketConn) error {
		calls.Add(1)
		b := make([]byte, MaxPayload)
		for {
			n, a, e := p.ReadFrom(b)
			if e != nil {
				return e
			}
			if _, e = p.WriteTo(b[:n], a); e != nil {
				return e
			}
		}
	}})
	if e != nil {
		p.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := s.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	return s, p.LocalAddr(), calls
}

func testClient(t *testing.T, remote net.Addr, limits Limits) *Client {
	t.Helper()
	c, e := NewClient(ClientConfig{ServerName: testName, User: User{Username: testUser, Password: testPassword}, Socket: testSocket(remote), Limits: limits})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := c.Close(); e != nil {
			t.Error(e)
		}
	})
	return c
}

func streamBytes(ctx context.Context, c *Client, dst access.Endpoint, size int, half bool) error {
	stream, e := c.Open(ctx, dst)
	if e != nil {
		return e
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(8 * time.Second))
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*31 + size)
	}
	result := make(chan error, 1)
	go func() {
		for off := 0; off < len(payload); {
			n := min(137, len(payload)-off)
			_, e := stream.Write(payload[off : off+n])
			if e != nil {
				result <- e
				return
			}
			off += n
		}
		var writeErr error
		if half {
			writeErr = stream.(interface{ CloseWrite() error }).CloseWrite()
		}
		result <- writeErr
	}()
	got := make([]byte, size)
	_, e = io.ReadFull(stream, got)
	if e != nil {
		return e
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("byte mismatch")
	}
	if e = <-result; e != nil {
		return e
	}
	if half {
		var b [1]byte
		if _, e = stream.Read(b[:]); e != io.EOF {
			return fmt.Errorf("FIN: %w", e)
		}
	}
	return nil
}

func TestSessionTCPMultiplexHalfCloseAndReconnect(t *testing.T) {
	s, a, _ := testServer(t, Limits{})
	c := testClient(t, a, Limits{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, n := range []int{1, 1200, 65536, 2 << 20} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			if e := streamBytes(ctx, c, access.Endpoint{Host: "target.test", Port: 80}, n, true); e != nil {
				t.Fatal(e)
			}
		})
	}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			if e := streamBytes(ctx, c, access.Endpoint{Host: "::1", Port: 80}, 2048+i, false); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	// Reset one stream, preserving siblings and the persistent connection.
	st, e := c.Open(ctx, access.Endpoint{Host: "127.0.0.1", Port: 80})
	if e != nil {
		t.Fatal(e)
	}
	st.Close()
	c.mu.Lock()
	old := c.current
	c.mu.Unlock()
	if e = streamBytes(ctx, c, access.Endpoint{Host: "127.0.0.1", Port: 80}, 17, false); e != nil {
		t.Fatal(e)
	}
	_ = old.conn.CloseWithError(0, "")
	<-old.conn.Context().Done()
	if e = streamBytes(ctx, c, access.Endpoint{Host: "127.0.0.1", Port: 80}, 128, true); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	fresh := c.current
	c.mu.Unlock()
	if old == fresh {
		t.Fatal("dead connection reused")
	}
	if e = s.Close(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestSessionUDPDomainIPv6BoundariesAndConcurrentAssociations(t *testing.T) {
	_, a, _ := testServer(t, Limits{})
	c := testClient(t, a, Limits{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, host := range []string{"127.0.0.1", "::1", "target.test", "other.test"} {
		wg.Go(func() {
			dst := access.Endpoint{Host: host, Port: 53}
			p, e := c.OpenPacket(ctx, dst)
			if e != nil {
				t.Error(e)
				return
			}
			defer p.Close()
			_ = p.SetDeadline(time.Now().Add(4 * time.Second))
			for _, size := range []int{0, 1, 1199, 1200} {
				data := bytes.Repeat([]byte{byte(size)}, size)
				if _, e = p.WriteTo(data, netaddr.UDP(dst)); e != nil {
					t.Error(e)
					return
				}
				b := make([]byte, 1200)
				n, reply, e := p.ReadFrom(b)
				if e != nil {
					t.Error(e)
					return
				}
				d, _ := netaddr.From(reply)
				if d != dst || !bytes.Equal(data, b[:n]) {
					t.Error("UDP bytes/address", d, dst)
				}
			}
			if _, e = p.WriteTo(make([]byte, 1201), netaddr.UDP(dst)); !errors.Is(e, ErrLimit) {
				t.Error("oversize", e)
			}
			if _, e = p.WriteTo([]byte{1}, netaddr.UDP(access.Endpoint{Host: "else.test", Port: 53})); !errors.Is(e, ErrProtocol) {
				t.Error("pin bypass", e)
			}
		})
	}
	wg.Wait()
}

func TestSessionAuthenticationAndTimeout(t *testing.T) {
	_, a, calls := testServer(t, Limits{HandshakeSeconds: 1})
	for _, which := range []string{"password", "username", "name"} {
		t.Run(which, func(t *testing.T) {
			cfg := ClientConfig{ServerName: testName, User: User{Username: testUser, Password: testPassword}, Socket: testSocket(a), Limits: Limits{HandshakeSeconds: 1}}
			switch which {
			case "password":
				cfg.User.Password = "wrong"
			case "username":
				cfg.User.Username = "wrong"
			case "name":
				cfg.ServerName = "wrong.test"
			}
			c, e := NewClient(cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if st, e := c.Open(ctx, access.Endpoint{Host: "target.test", Port: 80}); e == nil {
				st.Close()
				t.Fatal("unauthorized accepted")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized dispatch")
	}
	silent, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer silent.Close()
	c := testClient(t, silent.LocalAddr(), Limits{HandshakeSeconds: 1})
	start := time.Now()
	if _, e = c.Open(context.Background(), access.Endpoint{Host: "target.test", Port: 80}); e == nil || time.Since(start) > 2*time.Second {
		t.Fatal("handshake timeout", e)
	}
}

func TestSessionDeadlinesCancellationAndClose(t *testing.T) {
	_, a, _ := testServer(t, Limits{UDPIdleSeconds: 2})
	c := testClient(t, a, Limits{MaxStreams: 1, UDPIdleSeconds: 2})
	ctx := context.Background()
	dst := access.Endpoint{Host: "target.test", Port: 80}
	st, e := c.Open(ctx, dst)
	if e != nil {
		t.Fatal(e)
	}
	pending, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, e = c.Open(pending, dst); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("stream quota cancellation", e)
	}
	st.Close()
	p, e := c.OpenPacket(ctx, dst)
	if e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { _, _, e := p.ReadFrom(make([]byte, 1)); result <- e }()
	_ = p.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if e = <-result; !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("live deadline", e)
	}
	_ = p.SetDeadline(time.Time{})
	go func() { _, _, e := p.ReadFrom(make([]byte, 1)); result <- e }()
	p.Close()
	if e = <-result; !errors.Is(e, net.ErrClosed) {
		t.Fatal("close wake", e)
	}
	p, e = c.OpenPacket(ctx, dst)
	if e != nil {
		t.Fatal(e)
	}
	go func() { _, _, e := p.ReadFrom(make([]byte, 1)); result <- e }()
	if e = <-result; !errors.Is(e, net.ErrClosed) {
		t.Fatal("idle", e)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 4 {
				conn, e := c.Open(ctx, dst)
				if e == nil {
					conn.Close()
				}
			}
		})
	}
	c.Close()
	wg.Wait()
	if _, e = c.Open(ctx, dst); !errors.Is(e, net.ErrClosed) {
		t.Fatal(e)
	}
}

func TestCIDBoundsCollisionRetirementAndReordering(t *testing.T) {
	// Exercise attacker-controlled state without a network or QUIC dependency.
	c := &connection{limits: Limits{MaxFlows: 2}, packets: map[*packet]bool{}, receive: map[uint16]destination{}, allocated: map[*packet]int{}}
	p := &packet{closed: make(chan struct{}), received: make(chan datagram, 32), last: time.Now()}
	c.packets[p] = true
	dst := access.Endpoint{Host: "domain.test", Port: 53}
	c.pending = []datagram{{id: 7, data: []byte{42}, at: time.Now()}, {id: 8, at: time.Now().Add(-2 * time.Second)}}
	if e := c.register(p, dst, 7); e != nil {
		t.Fatal(e)
	}
	if len(c.pending) != 0 || len(p.received) != 1 {
		t.Fatal("pending reorder/expiry")
	}
	if e := c.register(p, access.Endpoint{Host: "other.test", Port: 53}, 7); !errors.Is(e, ErrProtocol) {
		t.Fatal("CID collision", e)
	}
	if _, e := c.allocate(p); e != nil {
		t.Fatal(e)
	}
	if _, e := c.allocate(p); e != nil {
		t.Fatal(e)
	}
	if _, e := c.allocate(p); !errors.Is(e, ErrLimit) {
		t.Fatal("aggregate quota", e)
	}
	c.remove(p)
	c.packets[p] = true
	if e := c.register(p, dst, 7); !errors.Is(e, ErrProtocol) {
		t.Fatal("retired CID reused", e)
	}
	if c.sent != 0 {
		t.Fatal("allocation leaked")
	}
	c.next = 65536
	if _, e := c.allocate(p); !errors.Is(e, ErrLimit) {
		t.Fatal("CID wrapped", e)
	}
}

func TestSessionMalformedStreamsVersionAndPlainTLS(t *testing.T) {
	_, a, calls := testServer(t, Limits{HandshakeSeconds: 1})
	c := testClient(t, a, Limits{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, e := c.session(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{{4, 1, 0, 0, 0, 0, 0, 0}, {5}, {255}, {1, 3, 0, 0, 80}, {1, 9}} {
		st, e := s.open(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_ = st.SetDeadline(time.Now().Add(time.Second))
		if _, e = st.Write(raw); e != nil {
			t.Fatal(e)
		}
		var b [1]byte
		if _, e = st.Read(b[:]); e == nil {
			t.Fatal("malformed accepted")
		}
		st.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("malformed dispatched")
	}
	if e = streamBytes(ctx, c, access.Endpoint{Host: "target.test", Port: 80}, 12, true); e != nil {
		t.Fatal("malformed poisoned session", e)
	}
	socket, _, e := testSocket(a)(ctx)
	if e != nil {
		t.Fatal(e)
	}
	tr := &quic.Transport{Conn: socket}
	defer tr.Close()
	defer socket.Close()
	tc := &tls.Config{ServerName: testName, NextProtos: []string{"h3"}, JLSConfig: &tls.JLSConfig{Enable: true, User: tls.JLSUser{Username: testUser, Password: testPassword}}}
	versionCtx, versionCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer versionCancel()
	if q, e := tr.Dial(versionCtx, a, tc, &quic.Config{Versions: []quic.Version{quic.Version2}}); e == nil {
		q.CloseWithError(0, "")
		t.Fatal("unsupported version")
	}
	plain, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer plain.Close()
	plainTransport := &quic.Transport{Conn: plain}
	defer plainTransport.Close()
	cert, e := camouflageCertificate()
	if e != nil {
		t.Fatal(e)
	}
	l, e := plainTransport.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, &quic.Config{})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	client := testClient(t, plain.LocalAddr(), Limits{HandshakeSeconds: 1})
	plainCtx, plainCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer plainCancel()
	if st, e := client.Open(plainCtx, access.Endpoint{Host: "target.test", Port: 80}); e == nil {
		st.Close()
		t.Fatal("ordinary TLS authorized proxy")
	}
}

type impairedPacket struct {
	net.PacketConn
	writes atomic.Int32
	pause  atomic.Bool
}

func (p *impairedPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	n := p.writes.Add(1)
	if p.pause.Load() || n%11 == 0 {
		return len(b), nil
	}
	if n%7 == 0 {
		time.Sleep(8 * time.Millisecond)
	}
	return p.PacketConn.WriteTo(b, a)
}

func TestSessionBoundedLossLatencyAndInterruption(t *testing.T) {
	_, a, _ := testServer(t, Limits{})
	var wrapper *impairedPacket
	c, e := NewClient(ClientConfig{ServerName: testName, User: User{Username: testUser, Password: testPassword}, Socket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, a, e := testSocket(a)(ctx)
		wrapper = &impairedPacket{PacketConn: p}
		return wrapper, a, e
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e = streamBytes(ctx, c, access.Endpoint{Host: "target.test", Port: 80}, 256<<10, true); e != nil {
		t.Fatal(e)
	}
	wrapper.pause.Store(true)
	timer := time.AfterFunc(150*time.Millisecond, func() { wrapper.pause.Store(false) })
	defer timer.Stop()
	if e = streamBytes(ctx, c, access.Endpoint{Host: "target.test", Port: 80}, 32768, true); e != nil {
		t.Fatal(e)
	}
	if wrapper.writes.Load() < 11 {
		t.Fatal("loss fixture not exercised")
	}
}

func FuzzCIDState(f *testing.F) {
	f.Add([]byte{0, 1, 0, 2, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1024 {
			return
		}
		c := &connection{limits: Limits{MaxFlows: 4}, packets: map[*packet]bool{}, receive: map[uint16]destination{}, allocated: map[*packet]int{}}
		p := &packet{closed: make(chan struct{}), received: make(chan datagram, 32)}
		c.packets[p] = true
		for i := 0; i+1 < len(b); i += 2 {
			id := uint16(b[i])<<8 | uint16(b[i+1])
			_ = c.register(p, access.Endpoint{Host: "target.test", Port: 53}, id)
			if b[i]&1 != 0 {
				c.remove(p)
				c.packets[p] = true
			}
			if len(c.receive) > 4 || len(c.pending) > 32 {
				t.Fatal("unbounded state")
			}
		}
	})
}

func TestSessionConnectionQuotaAndParentCancellation(t *testing.T) {
	s, a, calls := testServer(t, Limits{MaxConnections: 1})
	first := testClient(t, a, Limits{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dst := access.Endpoint{Host: "target.test", Port: 80}
	if e := streamBytes(ctx, first, dst, 17, true); e != nil {
		t.Fatal(e)
	}
	second := testClient(t, a, Limits{})
	st, e := second.Open(ctx, dst)
	if e == nil {
		defer st.Close()
		_ = st.SetDeadline(time.Now().Add(time.Second))
		_, _ = st.Write([]byte{1})
		var b [1]byte
		if _, e = st.Read(b[:]); e == nil {
			t.Fatal("connection quota bypass")
		}
	}
	s.mu.Lock()
	count := len(s.connections)
	s.mu.Unlock()
	if count > 1 || calls.Load() != 1 {
		t.Fatal("quota", count, calls.Load())
	}
	// Parent cancellation closes active streams and joins accept/packet workers.
	s.cancel()
	if e = s.Close(ctx); e != nil {
		t.Fatal(e)
	}
	if first.current.conn.Context().Err() == nil {
		select {
		case <-first.current.conn.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("parent did not close peer")
		}
	}
}
