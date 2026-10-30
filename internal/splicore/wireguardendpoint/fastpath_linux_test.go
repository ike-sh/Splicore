//go:build linux && with_gvisor

package wireguardendpoint

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func requireFastpath(t *testing.T) {
	t.Helper()
	if os.Getenv("SPLICORE_PHASE36_KERNEL") != "1" {
		t.Skip("requires explicit privileged Linux kernel qualification")
	}
}

func fastConfig(t *testing.T) E.WireGuard {
	t.Helper()
	key, _ := testKeys(t)
	_, public := testKeys(t)
	return E.WireGuard{Backend: E.Kernel, Tag: "fastpath", PrivateKey: key, Addresses: []string{"10.36.0.1/32", "fd36::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: public, AllowedIPs: []string{"10.36.0.2/32", "fd36::2/128"}}}}
}

func fastEndpoint(t *testing.T, c E.WireGuard, options Options) *Endpoint {
	t.Helper()
	if options.Dispatcher == nil {
		options.Dispatcher = &echoDispatcher{}
	}
	if options.Underlay == nil {
		options.Underlay = underlay.New()
	}
	e, err := New(context.Background(), c, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closedStatus(t, e) })
	if err = e.Start(context.Background()); err != nil {
		t.Fatalf("%v cause=%v", err, errors.Unwrap(err))
	}
	return e
}

func fastPair(t *testing.T, aBackend, bBackend E.WireGuardBackend, psk bool, outer string) (*Endpoint, *Endpoint) {
	t.Helper()
	ac, bc := fastConfig(t), fastConfig(t)
	ac.Backend, bc.Backend = aBackend, bBackend
	ac.Tag, bc.Tag = "fast-a", "fast-b"
	bc.Addresses = []string{"10.36.0.2/32", "fd36::2/128"}
	ak, bk := wgtypes.Key(ac.PrivateKey.Reveal()), wgtypes.Key(bc.PrivateKey.Reveal())
	ac.Peers[0].PublicKey, bc.Peers[0].PublicKey = bk.PublicKey().String(), ak.PublicKey().String()
	bc.Peers[0].AllowedIPs = []string{"10.36.0.1/32", "fd36::1/128"}
	if psk {
		key, _ := testKeys(t)
		ac.Peers[0].PreSharedKey, bc.Peers[0].PreSharedKey = key, key
	}
	b := fastEndpoint(t, bc, Options{})
	ac.Peers[0].Endpoint = net.JoinHostPort(outer, itoa(b.Status().ListenPort))
	a := fastEndpoint(t, ac, Options{})
	return a, b
}

func TestPhase36KernelTraffic(t *testing.T) {
	requireFastpath(t)
	for _, pairing := range []struct {
		name string
		a, b E.WireGuardBackend
	}{{"kernel-kernel", E.Kernel, E.Kernel}, {"kernel-userspace", E.Kernel, E.Userspace}, {"userspace-kernel", E.Userspace, E.Kernel}, {"auto-kernel", E.Auto, E.Kernel}} {
		for _, outer := range []string{"127.0.0.1", "::1"} {
			for _, psk := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/psk-%t", pairing.name, outer, psk), func(t *testing.T) {
					a, b := fastPair(t, pairing.a, pairing.b, psk, outer)
					for _, ip := range []string{"10.36.0.2", "fd36::2"} {
						transferTCP(t, a, ip)
						transferUDP(t, a, ip, 1200)
					}
					for _, ip := range []string{"10.36.0.1", "fd36::1"} {
						transferTCP(t, b, ip)
						transferUDP(t, b, ip, 512)
					}
					for _, e := range []*Endpoint{a, b} {
						s := e.Status()
						if s.Peers[0].LastHandshake.IsZero() || s.Peers[0].RXBytes == 0 || s.Peers[0].TXBytes == 0 {
							t.Fatalf("missing counters %+v", s)
						}
						if e.config.RequestedBackend() != E.Userspace {
							if e.device != nil || e.stack != nil || e.tun != nil || e.bind != nil || s.Selected != E.Kernel || s.Namespace == s.BirthNamespace {
								t.Fatalf("kernel data plane invariant %+v", s)
							}
							k := e.backend.(*kernelBackend)
							links, err := k.links.LinkList()
							if err != nil || len(links) != 2 {
								t.Fatalf("cleartext namespace external interface: links=%d err=%v", len(links), err)
							}
							if s.InterfaceIndex == 0 || len(s.InterfaceName) > 15 || s.ListenPort == 0 {
								t.Fatal("missing kernel metadata")
							}
						}
					}
				})
			}
		}
	}
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
	for _, class := range []Availability{KernelUnavailable, InsufficientPrivilege, NetNSUnavailable, NetlinkUnavailable, UnsupportedPlatform} {
		if !fallbackEligible(&BackendError{Class: class}) {
			t.Fatalf("missing fallback %s", class)
		}
	}
	if fallbackEligible(context.Canceled) {
		t.Fatal("cancellation fallback")
	}
}

func TestPhase36Unavailable(t *testing.T) {
	if os.Getenv("SPLICORE_PHASE36_CAP_CHILD") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(executable, "-test.run=^TestPhase36Unavailable$", "-test.v")
		cmd.Env = append(os.Environ(), "SPLICORE_PHASE36_CAP_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("capability child: %v %s", err, out)
		}
		return
	}
	if os.Geteuid() == 0 {
		if err := syscall.Setresgid(65534, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Setresuid(65534, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []E.WireGuardBackend{E.Kernel, E.Auto} {
		c := fastConfig(t)
		c.Backend = mode
		e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
		if err != nil {
			t.Fatal(err)
		}
		err = e.Start(context.Background())
		if mode == E.Kernel {
			var domain *BackendError
			if !errors.As(err, &domain) || domain.Class != InsufficientPrivilege || !errors.Is(err, unix.EPERM) {
				t.Fatalf("kernel unavailable: %v", err)
			}
		} else if err != nil || e.Status().Selected != E.Userspace || e.Status().Availability != InsufficientPrivilege {
			t.Fatalf("auto fallback: err=%v status=%+v", err, e.Status())
		}
		closedStatus(t, e)
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

func TestPhase36Rollback(t *testing.T) {
	requireFastpath(t)
	for _, step := range []string{"namespace", "link-created", "link", "move", "start", "configure", "loopback", "address", "route", "listener", "active"} {
		t.Run(step, func(t *testing.T) {
			c := fastConfig(t)
			e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := newKernelBackend(e, c)
			k := raw.(*kernelBackend)
			injected := errors.New("injected")
			k.fault = func(s string) error {
				if s == step {
					return injected
				}
				return nil
			}
			err = k.Prepare(context.Background())
			if err == nil {
				err = k.Start(context.Background())
			}
			if !errors.Is(err, injected) {
				t.Fatalf("step %s: %v", step, err)
			}
			if err = k.Close(); err != nil {
				t.Fatal(err)
			}
			if err = k.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = netlink.LinkByName(k.name); err == nil {
				t.Fatal("stale birth link")
			}
			if k.ns != -1 {
				t.Fatal("stale namespace")
			}
			closedStatus(t, e)
		})
	}
}

func TestPhase36NamespaceRestore(t *testing.T) {
	requireFastpath(t)
	c := fastConfig(t)
	e := fastEndpoint(t, c, Options{})
	k := e.backend.(*kernelBackend)
	for _, mode := range []string{"success", "socket", "bind", "connect", "panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := namespaceRun(ctx, k.ns, func() error {
				fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err != nil {
					return err
				}
				inode := namespaceInode(fd)
				_ = unix.Close(fd)
				if inode != k.meta.Namespace {
					return errors.New("wrong namespace")
				}
				switch mode {
				case "socket":
					_, err = unix.Socket(-1, unix.SOCK_STREAM, 0)
					return err
				case "bind":
					s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
					if err != nil {
						return err
					}
					defer unix.Close(s)
					return unix.Bind(s, &unix.SockaddrInet4{Addr: [4]byte{192, 0, 2, 1}})
				case "connect":
					_, err := (&net.Dialer{Timeout: time.Millisecond}).DialContext(ctx, "tcp4", "192.0.2.1:1")
					return err
				case "panic":
					panic("test")
				case "cancel":
					cancel()
				}
				return nil
			})
			if (err == nil) != (mode == "success") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
			entries, _ := os.ReadDir("/proc/self/task")
			for _, entry := range entries {
				target, err := os.Readlink("/proc/self/task/" + entry.Name() + "/ns/net")
				if err == nil && target != fmt.Sprintf("net:[%d]", k.meta.BirthNamespace) {
					t.Fatalf("thread %s leaked into %s", entry.Name(), target)
				}
			}
		})
	}
}

func TestPhase36KernelChurn100(t *testing.T) {
	requireFastpath(t)
	a, b := fastPair(t, E.Kernel, E.Kernel, false, "127.0.0.1")
	transferUDP(t, a, "10.36.0.2", 64)
	closedStatus(t, a)
	closedStatus(t, b)
	runtime.GC()
	baseG, baseFD := runtime.NumGoroutine(), fdCount()
	baseline := fastHostState(t)
	for i := range 100 {
		a, b := fastPair(t, E.Kernel, E.Kernel, i%2 == 0, "127.0.0.1")
		transferUDP(t, a, "10.36.0.2", 64)
		transferTCP(t, b, "fd36::1")
		closedStatus(t, a)
		closedStatus(t, b)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 5 {
				a, b := fastPair(t, E.Kernel, E.Kernel, false, "127.0.0.1")
				transferUDP(t, a, "fd36::2", 64)
				closedStatus(t, a)
				closedStatus(t, b)
			}
		})
	}
	wg.Wait()
	runtime.GC()
	if got := fdCount(); got != baseFD {
		t.Fatalf("FD growth %d -> %d", baseFD, got)
	}
	until := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baseG && time.Now().Before(until) {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseG {
		t.Fatalf("goroutine growth %d -> %d", baseG, got)
	}
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Alias, "splicore:") {
			t.Fatal("stale interface")
		}
	}
	if final := fastHostState(t); final != baseline {
		t.Fatal("host state changed across 100 lifecycle iterations")
	}
	t.Logf("100 sequential cycles + 20 concurrent cycles; FD=%d/%d goroutines=%d/%d", baseFD, fdCount(), baseG, runtime.NumGoroutine())
}

func TestPhase36KernelDestinationIsolation(t *testing.T) {
	requireFastpath(t)
	a, _ := fastPair(t, E.Kernel, E.Kernel, false, "127.0.0.1")
	if c, err := a.DialContext(context.Background(), access.Endpoint{Host: "192.0.2.1", Port: 443}); err == nil {
		c.Close()
		t.Fatal("AllowedIPs escaped")
	}
}
