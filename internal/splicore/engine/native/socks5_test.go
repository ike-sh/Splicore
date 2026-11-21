package native

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func socks5Intent(t *testing.T) ports.RuntimeIntent {
	t.Helper()
	intent := testfixture.MieruIntent(t, "tcp")
	intent.Inbound.Protocol = proxy.Key("socks5")
	intent.Inbound.Settings.Data = json.RawMessage(`{"auth":true,"udp":false}`)
	return intent
}

func TestManagedSOCKS5AuthenticationAndRouting(t *testing.T) {
	intent := socks5Intent(t)
	compiler := SOCKS5Compiler{}
	ctx := underlay.WithFactory(t.Context(), underlay.New())
	if _, err := compiler.Compile(ctx, intent); err == nil {
		t.Fatal("SOCKS5 compiled without committed binding admission")
	}
	var allowed atomic.Bool
	allowed.Store(true)
	intent.AuthorizeBinding = func(_ context.Context, b access.Binding) bool { return b.ID == intent.Bindings[0].ID && allowed.Load() }
	if _, err := compiler.Compile(t.Context(), intent); err == nil {
		t.Fatal("SOCKS5 compiled without protected target underlay")
	}
	pair, err := proxy.Pair(intent.Credentials[0])
	if err != nil {
		t.Fatal(err)
	}

	echo := testfixture.TCP(t)
	routes := make(chan string, 4)
	ctx = ports.WithTargetRouter(ctx, func(ctx context.Context, network, address string, fallback ports.TargetDialer) (net.Conn, error) {
		if address == "route-to-listener.example:12345" {
			endpoint := intent.Inbound.Listeners[0].Endpoint
			return fallback.DialContext(ctx, network, net.JoinHostPort(endpoint.Host, portString(endpoint.Port)))
		}
		routes <- network + " " + address
		return fallback.DialContext(ctx, network, echo.Addr().String())
	})
	prepared, err := compiler.Compile(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	handle := prepared.(*socks5Handle)
	defer handle.Close(context.Background())
	if err := handle.Start(ctx); err != nil {
		t.Fatal(err)
	}
	handle.Activate()

	connect := func(t *testing.T) net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", handle.listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		return conn
	}
	exchange := func(t *testing.T, conn net.Conn, send, want []byte) {
		t.Helper()
		if err := socks5.WriteFull(conn, send); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(want))
		if _, err := io.ReadFull(conn, reply); err != nil || !slices.Equal(reply, want) {
			t.Fatalf("SOCKS5 response %v, expected %v: %v", reply, want, err)
		}
	}
	t.Run("no auth", func(t *testing.T) {
		exchange(t, connect(t), []byte{5, 1, 0}, []byte{5, 255})
	})
	t.Run("wrong password and pipelined CONNECT", func(t *testing.T) {
		conn := connect(t)
		exchange(t, conn, []byte{5, 2, 0, 2}, []byte{5, 2})
		auth := append([]byte{1, byte(len(pair.Username))}, pair.Username...)
		auth = append(auth, 1, 'x')
		dst, err := address.MarshalSOCKS(access.Endpoint{Host: "must-not-resolve.example", Port: 443})
		if err != nil {
			t.Fatal(err)
		}
		auth = append(append(auth, 5, socks5.Connect, 0), dst...)
		exchange(t, conn, auth, []byte{1, 1})
		var extra [1]byte
		if n, err := conn.Read(extra[:]); err == nil || n != 0 {
			t.Fatal("CONNECT was processed after failed authentication")
		}
	})
	negotiate := func(t *testing.T, conn net.Conn, status byte) {
		t.Helper()
		exchange(t, conn, []byte{5, 1, 2}, []byte{5, 2})
		auth := append([]byte{1, byte(len(pair.Username))}, pair.Username...)
		auth = append(append(auth, byte(len(pair.Password))), pair.Password...)
		defer clear(auth)
		exchange(t, conn, auth, []byte{1, status})
	}
	for _, test := range []struct {
		name  string
		frame []byte
		code  byte
	}{
		{"UDP associate", []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}, socks5.UnsupportedCommand},
		{"BIND", []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}, socks5.UnsupportedCommand},
		{"invalid ATYP", []byte{5, 1, 0, 99}, socks5.UnsupportedAddress},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := connect(t)
			negotiate(t, conn, 0)
			exchange(t, conn, test.frame, []byte{5, test.code, 0, 1, 0, 0, 0, 0, 0, 0})
		})
	}
	t.Run("revoked after compile", func(t *testing.T) {
		allowed.Store(false)
		defer allowed.Store(true)
		negotiate(t, connect(t), 1)
	})
	t.Run("own listener blocked before routing", func(t *testing.T) {
		conn := connect(t)
		negotiate(t, conn, 0)
		address, err := address.MarshalSOCKS(intent.Inbound.Listeners[0].Endpoint)
		if err != nil {
			t.Fatal(err)
		}
		exchange(t, conn, append([]byte{5, 1, 0}, address...), []byte{5, socks5.NotAllowed, 0, 1, 0, 0, 0, 0, 0, 0})
	})
	if len(routes) != 0 {
		t.Fatal("rejected SOCKS5 traffic reached routing")
	}
	t.Run("routed self peer blocked before connecting", func(t *testing.T) {
		conn := connect(t)
		negotiate(t, conn, 0)
		dst, err := address.MarshalSOCKS(access.Endpoint{Host: "route-to-listener.example", Port: 12345})
		if err != nil {
			t.Fatal(err)
		}
		exchange(t, conn, append([]byte{5, 1, 0}, dst...), []byte{5, socks5.NotAllowed, 0, 1, 0, 0, 0, 0, 0, 0})
	})

	t.Run("concurrent CONNECT targets", func(t *testing.T) {
		for _, host := range []string{"127.0.0.1", "::1", "route-me.example"} {
			t.Run(host, func(t *testing.T) {
				t.Parallel()
				conn := connect(t)
				if _, err := socks5.ClientHandshake(conn, socks5.Connect, access.Endpoint{Host: host, Port: 12345}, pair); err != nil {
					t.Fatal(err)
				}
				exchange(t, conn, []byte("SOCKS5 relay"), []byte("SOCKS5 relay"))
			})
		}
	})
	var routed []string
	for len(routes) > 0 {
		routed = append(routed, <-routes)
	}
	slices.Sort(routed)
	if !slices.Equal(routed, []string{"tcp 127.0.0.1:12345", "tcp [::1]:12345", "tcp route-me.example:12345"}) {
		t.Fatalf("unexpected SOCKS5 routing: %v", routed)
	}
	if stats := handle.BindingStats(intent.Bindings[0].ID); stats.Upload == 0 || stats.Download == 0 {
		t.Fatal("authenticated payload was not attributed")
	}

	conn := connect(t)
	exchange(t, conn, []byte{5, 1, 2}, []byte{5, 2})
	if err := handle.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var extra [1]byte
	if _, err := conn.Read(extra[:]); err != io.EOF {
		t.Fatalf("shutdown did not release the pending handshake: %v", err)
	}
}

func TestManagedSOCKS5ConnectionBoundsAndCancellation(t *testing.T) {
	intent := socks5Intent(t)
	intent.AuthorizeBinding = func(context.Context, access.Binding) bool { return true }
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	ctx = underlay.WithFactory(ctx, underlay.New())
	entered := make(chan struct{}, socks5SourceHandshakeLimit+1)
	ctx = ports.WithTargetRouter(ctx, func(ctx context.Context, _, _ string, _ ports.TargetDialer) (net.Conn, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	prepared, err := (SOCKS5Compiler{}).Compile(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	handle := prepared.(*socks5Handle)
	t.Cleanup(func() { _ = handle.Close(context.Background()) })
	endpoint := intent.Inbound.Listeners[0].Endpoint
	listen := net.JoinHostPort(endpoint.Host, portString(endpoint.Port))
	occupied, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	err = handle.Start(ctx)
	_ = occupied.Close()
	var problem *identity.Error
	if !errors.As(err, &problem) || problem.Code != identity.PortConflict || handle.Health(ctx) == nil {
		t.Fatal("occupied SOCKS5 port did not fail closed", err)
	}
	if err := handle.Start(ctx); err != nil {
		t.Fatal("listener did not recover after port conflict", err)
	}
	handle.Activate()
	pair, err := proxy.Pair(intent.Credentials[0])
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, socks5SourceHandshakeLimit)
	for range socks5SourceHandshakeLimit {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listen)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		go func() {
			_, err := socks5.ClientHandshake(conn, socks5.Connect, access.Endpoint{Host: "pending.example", Port: 443}, pair)
			finished <- err
		}()
		select {
		case <-entered:
		case err := <-finished:
			t.Fatal("handshake ended before the protected target dial", err)
		case <-ctx.Done():
			t.Fatal("handshake never reached protected target dial", ctx.Err())
		}
	}
	extra, err := net.DialTimeout("tcp", listen, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = extra.SetDeadline(time.Now().Add(time.Second))
	_, _ = extra.Write([]byte{5, 1, 2})
	var response [2]byte
	n, rejection := extra.Read(response[:])
	_ = extra.Close()
	if n != 0 || rejection == nil {
		t.Fatal("excess concurrent connection passed admission")
	}
	if timeout, ok := rejection.(net.Error); ok && timeout.Timeout() {
		t.Fatal("excess connection waited for a handshake timeout")
	}
	if err := handle.Close(ctx); err != nil {
		t.Fatal("shutdown failed to join canceled target dials", err)
	}
	for range socks5SourceHandshakeLimit {
		select {
		case err := <-finished:
			if err == nil {
				t.Fatal("shutdown produced a successful CONNECT")
			}
		case <-ctx.Done():
			t.Fatal("shutdown left pending clients", ctx.Err())
		}
	}
	if stats := handle.Stats(); stats.Active != 0 || stats.Sessions != 0 {
		t.Fatal("canceled CONNECT leaked an active session")
	}
	free, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal("shutdown did not release the SOCKS5 port", err)
	}
	_ = free.Close()
}
