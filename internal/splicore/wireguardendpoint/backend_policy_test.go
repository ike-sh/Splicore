//go:build with_gvisor

package wireguardendpoint

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Retain shared validation, DNS ordering and fail-closed fallback assertions
// while the unqualified kernel implementation is archived.
func TestExcludedKernelActivationAndAutoUserspaceTraffic(t *testing.T) {
	explicit := fastConfig(t)
	e, err := New(context.Background(), explicit, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closedStatus(t, e) })
	err = e.Start(context.Background())
	if backendAvailability(err) != KernelNotQualified || e.Status().Selected != "" || e.Status().State != Closed {
		t.Fatalf("explicit unqualified kernel activation: error=%v status=%+v", err, e.Status())
	}

	ac, bc := fastConfig(t), fastConfig(t)
	ac.Backend, bc.Backend = E.Auto, E.Userspace
	bc.Addresses = []string{"10.36.0.2/32", "fd36::2/128"}
	ak, bk := wgtypes.Key(ac.PrivateKey.Reveal()), wgtypes.Key(bc.PrivateKey.Reveal())
	ac.Peers[0].PublicKey, bc.Peers[0].PublicKey = bk.PublicKey().String(), ak.PublicKey().String()
	bc.Peers[0].AllowedIPs = []string{"10.36.0.1/32", "fd36::1/128"}
	b, err := New(context.Background(), bc, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closedStatus(t, b) })
	if err = b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ac.Peers[0].Endpoint = net.JoinHostPort("127.0.0.1", itoa(b.Status().ListenPort))
	a, err := New(context.Background(), ac, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closedStatus(t, a) })
	if err = a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := a.Status(); status.Selected != E.Userspace || status.Availability != KernelNotQualified || status.State != Active {
		t.Fatalf("auto did not report qualified userspace fallback: %+v", status)
	}
	for _, ip := range []string{"10.36.0.2", "fd36::2"} {
		transferTCP(t, a, ip)
		transferUDP(t, a, ip, 64)
	}
	for _, ip := range []string{"10.36.0.1", "fd36::1"} {
		transferTCP(t, b, ip)
		transferUDP(t, b, ip, 64)
	}
}

func fastConfig(t *testing.T) E.WireGuard {
	t.Helper()
	key, _ := testKeys(t)
	_, public := testKeys(t)
	return E.WireGuard{Backend: E.Kernel, Tag: "fastpath", PrivateKey: key, Addresses: []string{"10.36.0.1/32", "fd36::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: public, AllowedIPs: []string{"10.36.0.2/32", "fd36::2/128"}}}}
}

func TestPhase36BackendValidation(t *testing.T) {
	c := fastConfig(t)
	for _, backend := range []E.WireGuardBackend{"", E.Userspace, E.Kernel, E.Auto, "invalid"} {
		c.Backend = backend
		if (c.Validate() == nil) != (backend != "invalid") {
			t.Fatalf("backend %q", backend)
		}
	}
	c.Backend = ""
	if c.RequestedBackend() != E.Userspace {
		t.Fatal("omitted backend changed")
	}
	for _, class := range []Availability{ConfigInvalid, RuntimeFailure, InterfaceCollision, CleanupFailure} {
		if fallbackEligible(&BackendError{Class: class}) {
			t.Fatalf("unsafe fallback %s", class)
		}
	}
	for _, class := range []Availability{KernelUnavailable, KernelNotQualified, InsufficientPrivilege, NetNSUnavailable, NetlinkUnavailable, UnsupportedPlatform} {
		if !fallbackEligible(&BackendError{Class: class}) {
			t.Fatalf("missing fallback %s", class)
		}
	}
	if fallbackEligible(context.Canceled) {
		t.Fatal("cancellation fallback")
	}
}

func TestPhase36CoreDNSBeforeSelection(t *testing.T) {
	for _, mode := range []E.WireGuardBackend{E.Userspace, E.Kernel, E.Auto} {
		c := fastConfig(t)
		c.Backend = mode
		c.Peers[0].Endpoint = "core.example:51820"
		sentinel := errors.New("resolver sentinel")
		calls := 0
		e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New(), LookupEndpoint: func(context.Context, string) ([]netip.Addr, error) { calls++; return nil, sentinel }})
		if err != nil {
			t.Fatal(err)
		}
		if err = e.Start(context.Background()); !errors.Is(err, sentinel) || calls != 1 || e.backend != nil {
			t.Fatalf("DNS failure masked mode=%s calls=%d err=%v", mode, calls, err)
		}
		closedStatus(t, e)
	}
}

func TestPhase36FixFallbackMatrix(t *testing.T) {
	for _, class := range []Availability{UnsupportedPlatform, KernelUnavailable, KernelNotQualified, InsufficientPrivilege, NetNSUnavailable, NetlinkUnavailable, NetfilterUnavailable, ConfigInvalid, RuntimeFailure, InterfaceCollision, CleanupFailure, NamespaceRestoreFailure} {
		t.Run(string(class), func(t *testing.T) {
			expected := class == UnsupportedPlatform || class == KernelUnavailable || class == KernelNotQualified || class == InsufficientPrivilege || class == NetNSUnavailable || class == NetlinkUnavailable || class == NetfilterUnavailable
			base := &BackendError{Class: class, Operation: "test", Cause: syscall.EPERM}
			if fallbackEligible(base) != expected || !errors.Is(base, syscall.EPERM) {
				t.Fatal("classification mismatch")
			}
			var errno syscall.Errno
			if !errors.As(base, &errno) || errno != syscall.EPERM {
				t.Fatal("causal errno type lost")
			}
			for _, fatal := range []error{&BackendError{Class: NamespaceRestoreFailure, Cause: syscall.EIO}, &BackendError{Class: CleanupFailure}, &BackendError{Class: RuntimeFailure}, context.Canceled, context.DeadlineExceeded, errors.New("corrupt state"), &resolutionError{cause: errors.New("Core DNS failure")}} {
				if fallbackEligible(errors.Join(base, fatal)) || fallbackEligible(errors.Join(fatal, base)) {
					t.Fatal("joined fatal error allowed fallback")
				}
			}
			joined := errors.Join(base, &BackendError{Class: NamespaceRestoreFailure, Cause: syscall.EIO})
			if backendAvailability(joined) != NamespaceRestoreFailure || !errors.Is(joined, syscall.EIO) {
				t.Fatal("restore failed to dominate")
			}
		})
	}
}
