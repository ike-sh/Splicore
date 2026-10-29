package native

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	snell "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func listenerSnell(t *testing.T, ctx context.Context, endpoint access.Endpoint, version int) *Handle {
	t.Helper()
	in := testfixture.MieruIntentAt(t, "tcp", endpoint)
	in.Inbound.Protocol = snell.Key(version)
	in.Inbound.Settings.Data = []byte(fmt.Sprintf(`{"version":%d}`, version))
	in.Credentials = in.Credentials[:1]
	in.Bindings = in.Bindings[:1]
	in.Credentials[0].Kind = access.PSK
	in.Credentials[0].Payload = access.PSKPayload{Key: secret.New("SyntheticListenerFailure12345")}
	p, err := (SnellCompiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := p.(*Handle)
	t.Cleanup(func() {
		if err := h.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return h
}

func TestSnellListenerErrnoRollbackAndRecovery(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			tcp, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			address := tcp.Addr().String()
			owner, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			endpoint := access.Endpoint{Host: host, Port: uint16(tcp.Addr().(*net.TCPAddr).Port)}
			h := listenerSnell(t, ctx, endpoint, 5)
			_ = tcp.Close()
			before, _ := os.ReadDir("/proc/self/fd")
			goroutines := runtime.NumGoroutine()
			err = h.Start(ctx)
			var domain *identity.Error
			var op *net.OpError
			var call *os.SyscallError
			if !errors.Is(err, syscall.EADDRINUSE) || !errors.As(err, &domain) || domain.Code != identity.PortConflict || !errors.As(err, &op) || !errors.As(err, &call) {
				t.Fatal("bind cause or domain classification lost", err)
			}
			if op.Op != "listen" || op.Net != "udp" || op.Addr.String() != address || call.Syscall != "bind" {
				t.Fatal("unexpected bind identity", op, call)
			}
			after, _ := os.ReadDir("/proc/self/fd")
			if len(after) != len(before) || h.listener != nil || h.quicProxy != nil || h.started || h.running.Load() || len(h.connections) != 0 {
				t.Fatal("failed attempt retained sockets, workers or state", len(before), len(after))
			}
			joined := make(chan struct{})
			go func() { h.wg.Wait(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("failed listener retained a worker")
			}
			t.Logf("handle=%p external_udp_owner=%p requested=%s op=%s network=%s syscall=%s errno=%d fd_baseline=%d fd_after=%d goroutines_before=%d goroutines_after=%d proxy=nil workers=joined", h, owner, address, op.Op, op.Net, call.Syscall, syscall.EADDRINUSE, len(before), len(after), goroutines, runtime.NumGoroutine())
			probe, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal("partial TCP listener survived failed UDP bind", err)
			}
			_ = probe.Close()
			duplicate, err := net.ListenPacket("udp", address)
			if duplicate != nil {
				_ = duplicate.Close()
			}
			if !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatal("failed runtime disturbed external UDP owner", err)
			}
			_ = owner.Close()
			if err := h.Start(ctx); err != nil {
				t.Fatal("explicit recovery on the same runtime object failed", err)
			}
			h.Activate()
			if err := h.Health(ctx); err != nil {
				t.Fatal(err)
			}
			if err := h.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(h.Start(ctx), net.ErrClosed) {
				t.Fatal("closed runtime cause lost")
			}
			probe, err = net.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			packet, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
		})
	}
}

func TestSnellListenerErrorClassificationAndChain(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		code  identity.Code
	}{
		{"address_in_use", syscall.EADDRINUSE, identity.PortConflict},
		{"permission", syscall.EACCES, identity.Unavailable},
		{"address_unavailable", syscall.EADDRNOTAVAIL, identity.Invalid},
		{"address_family", syscall.EAFNOSUPPORT, identity.Invalid},
		{"invalid_address", &net.AddrError{Err: "invalid port", Addr: "synthetic"}, identity.Invalid},
		{"closed", net.ErrClosed, identity.Unavailable},
		{"other", syscall.ENOBUFS, identity.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := &os.SyscallError{Syscall: "bind", Err: tc.cause}
			op := &net.OpError{Op: "listen", Net: "udp", Addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, Err: call}
			err := snellListenError("Snell QUIC listener start failed", op)
			var domain *identity.Error
			var gotOp *net.OpError
			var gotCall *os.SyscallError
			if !errors.Is(err, tc.cause) || !errors.As(err, &domain) || domain.Code != tc.code || !errors.As(err, &gotOp) || gotOp != op || !errors.As(err, &gotCall) || gotCall != call {
				t.Fatal("listener cause/object identity lost", err)
			}
		})
	}
}

func TestSnellNonConflictListenErrorIsNotPortConflict(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	h := listenerSnell(t, ctx, access.Endpoint{Host: "192.0.2.250", Port: 24000}, 5)
	err := h.Start(ctx)
	var domain *identity.Error
	if !errors.Is(err, syscall.EADDRNOTAVAIL) || !errors.As(err, &domain) || domain.Code != identity.Invalid {
		t.Fatal("non-conflict bind was misclassified", err)
	}
}

func TestSnellListenerConcurrentStartClose(t *testing.T) {
	for range 16 {
		ctx := underlay.WithFactory(context.Background(), underlay.New())
		probe, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := probe.Addr().String()
		packet, err := net.ListenPacket("udp4", address)
		if err != nil {
			probe.Close()
			t.Fatal(err)
		}
		h := listenerSnell(t, ctx, access.Endpoint{Host: "127.0.0.1", Port: uint16(probe.Addr().(*net.TCPAddr).Port)}, 5)
		_ = packet.Close()
		_ = probe.Close()
		barrier := make(chan struct{})
		started, closed := make(chan error, 1), make(chan error, 1)
		go func() { <-barrier; started <- h.Start(ctx) }()
		go func() { <-barrier; closed <- h.Close(ctx) }()
		close(barrier)
		if err := <-started; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		probe, err = net.Listen("tcp4", address)
		if err != nil {
			t.Fatal("concurrent shutdown retained TCP", err)
		}
		_ = probe.Close()
		packet, err = net.ListenPacket("udp4", address)
		if err != nil {
			t.Fatal("concurrent shutdown retained UDP", err)
		}
		_ = packet.Close()
	}
}
