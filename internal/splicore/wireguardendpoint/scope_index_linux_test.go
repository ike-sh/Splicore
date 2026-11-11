//go:build linux && with_gvisor

package wireguardendpoint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Both private namespaces deliberately own the same interface name. Fill target
// indices before movement, so the two authoritative indices differ and Linux
// must reallocate at least one birth index. All fixtures live in disposable netns.
func indexedPair(t *testing.T, padA, padB int) (*Endpoint, *Endpoint) {
	t.Helper()
	ac, bc := fastConfig(t), fastConfig(t)
	ac.Addresses, bc.Addresses = []string{"fe80::1/128", "10.36.0.1/32", "fd36::1/128"}, []string{"fe80::2/128", "10.36.0.2/32", "fd36::2/128"}
	ak, bk := wgtypes.Key(ac.PrivateKey.Reveal()), wgtypes.Key(bc.PrivateKey.Reveal())
	ac.Peers[0].PublicKey, bc.Peers[0].PublicKey = bk.PublicKey().String(), ak.PublicKey().String()
	ac.Peers[0].AllowedIPs, bc.Peers[0].AllowedIPs = bc.Addresses, ac.Addresses
	start := func(c E.WireGuard, pad int) *Endpoint {
		e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closedStatus(t, e) })
		birthIndex := 0
		e.kernelFactory = func(e *Endpoint, c E.WireGuard) (WireGuardBackend, error) {
			raw, err := newKernelBackend(e, c)
			if err != nil {
				return nil, err
			}
			k := raw.(*kernelBackend)
			k.name = "spwscope"
			k.fault = func(stage string) error {
				if stage == "namespace" {
					return namespaceRun(context.Background(), k.ns, func() error {
						for i := range pad {
							attrs := netlink.NewLinkAttrs()
							attrs.Name = fmt.Sprintf("pad%d", i)
							if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
								return err
							}
						}
						return nil
					})
				}
				if stage == "link" {
					birthIndex = k.link.Attrs().Index
					// Force a birth-index collision and advance the target's
					// allocator to a distinct range for each private namespace.
					if _, lookup := k.links.LinkByIndex(birthIndex); lookup != nil {
						attrs := netlink.NewLinkAttrs()
						attrs.Name, attrs.Index = "blockbirth", birthIndex
						if err := k.links.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
							return err
						}
					}
					attrs := netlink.NewLinkAttrs()
					attrs.Name, attrs.Index = "scopealloc", 10000+pad*1000+birthIndex
					if err := k.links.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
						return err
					}
				}
				return nil
			}
			return k, nil
		}
		if err = e.Start(context.Background()); err != nil {
			t.Fatalf("start: %v cause=%v", err, errors.Unwrap(err))
		}
		t.Logf("scope-move name=%s birth_ifindex=%d target_ifindex=%d namespace=%d", e.Status().InterfaceName, birthIndex, e.Status().InterfaceIndex, e.Status().Namespace)
		return e
	}
	b := start(bc, padB)
	ac.Peers[0].Endpoint = net.JoinHostPort("127.0.0.1", itoa(b.Status().ListenPort))
	a := start(ac, padA)
	if a.Status().InterfaceIndex == b.Status().InterfaceIndex {
		t.Fatal("fixture must use different indices")
	}
	return a, b
}

func scopeDummy(t *testing.T, name string, index int) netlink.Link {
	t.Helper()
	attrs := netlink.NewLinkAttrs()
	attrs.Name, attrs.Index = name, index
	d := &netlink.Dummy{LinkAttrs: attrs}
	if err := netlink.LinkAdd(d); err != nil {
		t.Fatal(err)
	}
	l, err := netlink.LinkByName(name)
	if err != nil || l.Attrs().Index != index {
		t.Fatalf("dummy index: %v %v", l, err)
	}
	return l
}

func scopeExchange(t *testing.T, a *Endpoint) {
	t.Helper()
	transferTCP(t, a, "fe80::2")
	transferUDP(t, a, "fe80::2", 128)
}

func TestPhase36ScopeCacheCollision(t *testing.T) {
	requireFastpath(t)
	if fixSubprocess(t, "TestPhase36ScopeCacheCollision", "SPLICORE_PHASE36_SCOPE_CACHE_CHILD") {
		return
	}
	warm, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = warm.Close()
	runtime.GC()
	baseFD, baseG := fdCount(), runtime.NumGoroutine()
	beforeTasks, _ := os.ReadDir("/proc/self/task")
	host := fastHostState(t)
	a, b := indexedPair(t, 1, 3)
	index := a.Status().InterfaceIndex
	name := strconv.Itoa(index)
	t.Run("cold", func(t *testing.T) { scopeExchange(t, a) })
	var dummy netlink.Link
	defer func() {
		if dummy != nil {
			_ = netlink.LinkDel(dummy)
		}
	}()
	for i, phase := range []string{"correct-looking", "conflicting", "stale", "refreshed"} {
		t.Run(phase, func(t *testing.T) {
			if dummy != nil {
				if err := netlink.LinkDel(dummy); err != nil {
					t.Fatal(err)
				}
				dummy = nil
			}
			wanted := index
			if i > 0 {
				wanted = index + 40 + i
			}
			dummy = scopeDummy(t, name, wanted)
			if phase != "stale" {
				got, err := net.InterfaceByName(name)
				if err != nil || got.Index != wanted {
					t.Fatal("public cache prime", got, err)
				}
			}
			iterations := 1
			if phase == "conflicting" {
				iterations = 100
			}
			for range iterations {
				if phase == "conflicting" {
					// Ordinary public lookups refresh conflicting mappings before each dial.
					if _, err := net.Interfaces(); err != nil {
						t.Fatal(err)
					}
					if _, err := net.InterfaceByName(name); err != nil {
						t.Fatal(err)
					}
				}
				scopeExchange(t, a)
			}
			t.Logf("cache=%s cached_name=%s current_birth_ifindex=%d owned_ifindex=%d TCP=%d UDP=%d", phase, name, wanted, index, iterations, iterations)
		})
	}
	// A realistic interface-name collision in the birth namespace is also inert.
	sameName := scopeDummy(t, "spwscope", index+80)
	if _, err := net.InterfaceByName("spwscope"); err != nil {
		t.Fatal(err)
	}
	scopeExchange(t, a)
	if err := netlink.LinkDel(sameName); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(dummy); err != nil {
		t.Fatal(err)
	}
	dummy = nil
	closedStatus(t, a)
	closedStatus(t, b)
	runtime.GC()
	until := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseG+2 && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	afterTasks, _ := os.ReadDir("/proc/self/task")
	if fdCount() > baseFD+1 || runtime.NumGoroutine() > baseG+2 || len(afterTasks) > len(beforeTasks)+8 {
		t.Fatalf("resource growth FD=%d/%d goroutines=%d/%d tasks=%d/%d", baseFD, fdCount(), baseG, runtime.NumGoroutine(), len(beforeTasks), len(afterTasks))
	}
	if fastHostState(t) != host {
		t.Fatal("birth namespace state changed")
	}
	t.Logf("collision-resource FD=%d/%d goroutines=%d/%d tasks=%d/%d", baseFD, fdCount(), baseG, runtime.NumGoroutine(), len(beforeTasks), len(afterTasks))
}

func TestPhase36ScopeConcurrentNamespaces(t *testing.T) {
	requireFastpath(t)
	a, b := indexedPair(t, 1, 3)
	c, d := indexedPair(t, 5, 7)
	for _, e := range []*Endpoint{a, b, c, d} {
		t.Logf("concurrent-owned name=%s index=%d ns=%d", e.Status().InterfaceName, e.Status().InterfaceIndex, e.Status().Namespace)
	}
	var wg sync.WaitGroup
	for _, e := range []*Endpoint{a, c} {
		wg.Go(func() {
			for range 25 {
				scopeExchange(t, e)
			}
		})
	}
	wg.Wait()
	for _, e := range []*Endpoint{b, d} {
		transferTCP(t, e, "fe80::1")
		transferUDP(t, e, "fe80::1", 100)
	}
}

func TestPhase36ScopeRecreate(t *testing.T) {
	requireFastpath(t)
	a, b := indexedPair(t, 1, 3)
	oldIndex := a.Status().InterfaceIndex
	scopeExchange(t, a)
	closedStatus(t, a)
	closedStatus(t, b)
	// Reuse the former numeric index for an unrelated birth interface.
	reused := scopeDummy(t, "oldwg", oldIndex)
	defer netlink.LinkDel(reused)
	if _, err := net.InterfaceByName("oldwg"); err != nil {
		t.Fatal(err)
	}
	c, d := indexedPair(t, 8, 10)
	if c.Status().InterfaceIndex == oldIndex {
		t.Fatal("recreation must change index")
	}
	scopeExchange(t, c)
	transferTCP(t, d, "fe80::1")
	transferUDP(t, d, "fe80::1", 128)
	if _, err := a.DialContext(context.Background(), access.Endpoint{Host: "fe80::2", Port: 12345}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old instance resurrected: %v", err)
	}
	t.Logf("recreated old_index=%d reused_by=oldwg new_index=%d", oldIndex, c.Status().InterfaceIndex)
}

func TestPhase36ScopeNegative(t *testing.T) {
	requireFastpath(t)
	a, _ := indexedPair(t, 1, 3)
	k := a.backend.(*kernelBackend)
	for _, index := range []uint32{0, 1} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			err := namespaceRun(context.Background(), k.ns, func() error {
				fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
				if err != nil {
					return err
				}
				defer unix.Close(fd)
				return unix.Bind(fd, &unix.SockaddrInet6{Addr: netip.MustParseAddr("fe80::1").As16(), ZoneId: index})
			})
			if err == nil {
				t.Fatal("wrong/missing scope unexpectedly bound")
			}
			t.Logf("negative scope=%d owned=%d error=%v", index, k.meta.InterfaceIndex, err)
		})
	}
	scopeExchange(t, a)
}

func TestPhase36ScopeMissingInterface(t *testing.T) {
	requireFastpath(t)
	a, _ := indexedPair(t, 1, 3)
	k := a.backend.(*kernelBackend)
	// Delete the owned link after activation: no zero scope, name substitution or
	// availability fallback is permitted. Restore an owned fixture for cleanup.
	link, err := k.ownedLink(k.links)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.links.LinkDel(link); err != nil {
		t.Fatal(err)
	}
	_, err = a.DialContext(context.Background(), access.Endpoint{Host: "fe80::2", Port: 12345})
	if err == nil || fallbackEligible(err) || a.Status().Selected != E.Kernel {
		t.Fatalf("missing interface: %v", err)
	}
	missingError := err
	attrs := netlink.NewLinkAttrs()
	attrs.Name, attrs.Alias, attrs.Index = k.name, k.marker, k.meta.InterfaceIndex
	if err = k.links.LinkAdd(&netlink.GenericLink{LinkAttrs: attrs, LinkType: "wireguard"}); err != nil {
		t.Fatal(err)
	}
	restored, err := k.links.LinkByName(k.name)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.links.LinkSetAlias(restored, k.marker); err != nil {
		t.Fatal(err)
	}
	if _, err = k.ownedLink(k.links); err != nil {
		t.Fatal(err)
	}
	t.Logf("deleted-owned-interface causal_error=%v fallback=false", missingError)
}

func TestPhase36ScopeSocketSemantics(t *testing.T) {
	requireFastpath(t)
	a, _ := indexedPair(t, 1, 3)
	target := access.Endpoint{Host: "fe80::2", Port: 12345}
	t.Run("large-half-close-remote-eof", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := a.DialContext(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		payload := bytes.Repeat([]byte("scope"), 200000)
		sent := make(chan error, 1)
		go func() {
			_, e := io.Copy(c, bytes.NewReader(payload))
			if e == nil {
				e = c.(interface{ CloseWrite() error }).CloseWrite()
			}
			sent <- e
		}()
		got, err := io.ReadAll(c)
		if sendErr := <-sent; sendErr != nil || err != nil || !bytes.Equal(payload, got) {
			t.Fatalf("large TCP n=%d write=%v read=%v", len(got), sendErr, err)
		}
	})
	t.Run("tcp-read-deadline", func(t *testing.T) {
		c, err := a.DialContext(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, err = c.Read(make([]byte, 1))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("TCP deadline: %v", err)
		}
	})
	t.Run("udp-repeat-deadline-close", func(t *testing.T) {
		p, err := a.ListenPacket(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		_ = p.SetDeadline(time.Now().Add(3 * time.Second))
		for i := range 10 {
			payload := bytes.Repeat([]byte{byte(i)}, 64+i)
			dst := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[fe80::2]:12345"))
			if _, err = p.WriteTo(payload, dst); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 256)
			n, _, err := p.ReadFrom(buf)
			if err != nil || !bytes.Equal(payload, buf[:n]) {
				t.Fatal("UDP repeat", err)
			}
		}
		_ = p.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, _, err = p.ReadFrom(make([]byte, 1))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("UDP deadline: %v", err)
		}
		_ = p.SetWriteDeadline(time.Now().Add(-time.Second))
		_, err = p.WriteTo([]byte("expired"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[fe80::2]:12345")))
		timeout, ok := err.(net.Error)
		if !errors.Is(err, os.ErrDeadlineExceeded) || !ok || !timeout.Timeout() {
			t.Fatalf("UDP write timeout contract: %T %v", err, err)
		}
		_ = p.SetDeadline(time.Time{})
		if err = p.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = p.WriteTo([]byte("closed"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[fe80::2]:12345"))); err == nil {
			t.Fatal("closed UDP wrote")
		}
	})
}

func TestPhase36ScopeConnectCancellation(t *testing.T) {
	requireFastpath(t)
	for _, mode := range []string{"before", "cancel", "cancel-with-deadline", "deadline", "close-backend", "close-raw-fd"} {
		t.Run(mode, func(t *testing.T) {
			// No reachable peer: connect stays EINPROGRESS in the WG namespace.
			e := fastEndpoint(t, func() E.WireGuard {
				c := fastConfig(t)
				c.Addresses = []string{"fe80::1/128"}
				c.Peers[0].AllowedIPs = []string{"fe80::2/128"}
				return c
			}(), Options{})
			k := e.backend.(*kernelBackend)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel-with-deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
			}
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
				defer cancel()
			}
			if mode == "before" {
				cancel()
			}
			result := make(chan error, 1)
			started := time.Now()
			if mode == "close-raw-fd" {
				go func() {
					result <- namespaceRun(ctx, k.ns, func() error {
						f, err := indexedSocket(netip.MustParseAddrPort("[fe80::1]:0"), uint32(k.meta.InterfaceIndex), unix.SOCK_STREAM, false)
						if err != nil {
							return err
						}
						defer f.Close()
						timer := time.AfterFunc(30*time.Millisecond, func() { _ = f.Close() })
						defer timer.Stop()
						return connectIndexed(ctx, f, &unix.SockaddrInet6{Addr: netip.MustParseAddr("fe80::2").As16(), Port: 12345, ZoneId: uint32(k.meta.InterfaceIndex)})
					})
				}()
			} else {
				go func() {
					c, err := e.DialContext(ctx, access.Endpoint{Host: "fe80::2", Port: 12345})
					if c != nil {
						_ = c.Close()
					}
					result <- err
				}()
			}
			switch mode {
			case "cancel", "cancel-with-deadline":
				time.AfterFunc(30*time.Millisecond, cancel)
			case "close-backend":
				time.AfterFunc(30*time.Millisecond, func() { _ = e.Close() })
			}
			select {
			case err := <-result:
				if err == nil || time.Since(started) > time.Second {
					t.Fatalf("connect mode=%s elapsed=%s err=%v", mode, time.Since(started), err)
				}
				if (mode == "before" || mode == "cancel" || mode == "cancel-with-deadline") && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel cause lost: %v", err)
				}
				if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("deadline cause lost: %v", err)
				}
				t.Logf("connect-cancellation mode=%s elapsed=%s error=%v", mode, time.Since(started), err)
			case <-time.After(2 * time.Second):
				t.Fatal("connect did not interrupt")
			}
		})
	}
}

func TestPhase36ScopeRestoreFailure(t *testing.T) {
	requireFastpath(t)
	if fixSubprocess(t, "TestPhase36ScopeRestoreFailure", "SPLICORE_PHASE36_SCOPE_RESTORE_CHILD") {
		return
	}
	for _, step := range []string{"tcp-socket", "udp-socket"} {
		t.Run(step, func(t *testing.T) {
			a, b := indexedPair(t, 1, 3)
			k := a.backend.(*kernelBackend)
			original, _ := os.Readlink("/proc/thread-self/ns/net")
			var tid int
			k.fault = func(stage string) error {
				if stage != step {
					return nil
				}
				tid = unix.Gettid()
				return denyWorkerSyscall(unix.SYS_SETNS, unix.EPERM)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var err error
			if step == "tcp-socket" {
				_, err = a.DialContext(ctx, access.Endpoint{Host: "fe80::2", Port: 12345})
			} else {
				_, err = a.ListenPacket(ctx, access.Endpoint{Host: "fe80::2", Port: 12345})
			}
			if backendAvailability(err) != NamespaceRestoreFailure || !errors.Is(err, unix.EPERM) || fallbackEligible(err) || a.Status().Selected != E.Kernel {
				t.Fatalf("scoped restore: %v", err)
			}
			assertWorkerGone(t, tid, original, b.Status().Namespace)
			closedStatus(t, a)
			closedStatus(t, b)
			t.Logf("scoped-restore stage=%s poisoned_tid=%d discarded=true fallback=false", step, tid)
		})
	}
}

func TestPhase36ScopeErrorFDPressure(t *testing.T) {
	requireFastpath(t)
	a, _ := indexedPair(t, 1, 3)
	k := a.backend.(*kernelBackend)
	before := fdCount()
	for range 100 {
		err := namespaceRun(context.Background(), k.ns, func() error {
			f, err := indexedSocket(netip.MustParseAddrPort("[fe80::1]:0"), 1, unix.SOCK_STREAM, false)
			if f != nil {
				_ = f.Close()
			}
			return err
		})
		if err == nil {
			t.Fatal("wrong-scope bind succeeded")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err = a.DialContext(ctx, access.Endpoint{Host: "fe80::2", Port: 12345}); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled dial: %v", err)
		}
	}
	if fdCount() != before {
		t.Fatalf("failed socket FD growth %d/%d", before, fdCount())
	}
	t.Logf("100 bind failures +100 canceled dials FD=%d/%d", before, fdCount())
}
