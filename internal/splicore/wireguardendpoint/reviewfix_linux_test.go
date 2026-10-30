//go:build linux && with_gvisor

package wireguardendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Keep m0 available to the deterministic subprocess probe in TestMain. This
// reservation exists only in that subprocess, never in the production package.
func init() {
	if os.Getenv("SPLICORE_PHASE36_FIX_M0") == "1" {
		runtime.LockOSThread()
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("SPLICORE_PHASE36_FIX_M0") != "1" {
		os.Exit(m.Run())
	}
	original, _ := os.Readlink("/proc/thread-self/ns/net")
	mainTID := unix.Gettid()
	var workerTID int
	var private string
	result := make(chan namespaceResult, 1)
	// Invoke the production worker on m0 itself, forcing its bounce branch.
	namespaceWorker(context.Background(), -1, func() error {
		workerTID = unix.Gettid()
		if workerTID == os.Getpid() {
			return errors.New("m0 was allowed to enter a namespace")
		}
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return err
		}
		private, _ = os.Readlink("/proc/thread-self/ns/net")
		return denyWorkerSyscall(unix.SYS_SETNS, unix.EPERM)
	}, result)
	r := <-result
	until := time.Now().Add(time.Second)
	for !errors.Is(unix.Tgkill(os.Getpid(), workerTID, 0), unix.ESRCH) && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	after, _ := os.Readlink("/proc/thread-self/ns/net")
	pass := mainTID == os.Getpid() && workerTID != mainTID && private != original && after == original && r.discardTID == workerTID && backendAvailability(r.err) == NamespaceRestoreFailure && errors.Is(unix.Tgkill(os.Getpid(), workerTID, 0), unix.ESRCH)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"m0_tid": mainTID, "worker_tid": workerTID, "original": original, "private": private, "m0_after": after, "discarded": pass, "pass": pass})
	if !pass {
		os.Exit(1)
	}
	os.Exit(0)
}

// Seccomp is installed on this locked test worker only, without TSYNC. It makes
// the actual restore syscall fail. Never install this policy on a reusable M.
func denyWorkerSyscall(number uintptr, errno unix.Errno) error {
	return workerFilter([]unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: uint32(number)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(errno)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	})
}

func workerFilter(code []unix.SockFilter) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	program := unix.SockFprog{Len: uint16(len(code)), Filter: &code[0]}
	_, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(code)
	if errno != 0 {
		return errno
	}
	return nil
}

func denyNetfilterSocket() error {
	// Deny every NETLINK_NETFILTER socket, including compatibility retries.
	return workerFilter([]unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 5, K: uint32(unix.SYS_SOCKET)},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 3, K: unix.AF_NETLINK},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 32},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.NETLINK_NETFILTER},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPROTONOSUPPORT)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	})
}

func fixSubprocess(t *testing.T, name, variable string) bool {
	t.Helper()
	if os.Getenv(variable) == "1" {
		return false
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), variable+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess: %v\n%s", err, out)
	}
	t.Logf("%s", out)
	return true
}

func assertWorkerGone(t *testing.T, tid int, original string, activeNamespaces ...uint64) {
	t.Helper()
	if tid == 0 || tid == os.Getpid() || !errors.Is(unix.Tgkill(os.Getpid(), tid, 0), unix.ESRCH) {
		t.Fatalf("poisoned worker was not discarded: pid=%d tid=%d", os.Getpid(), tid)
	}
	paths, err := filepath.Glob("/proc/self/task/*/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		namespace, err := os.Readlink(path)
		allowed := namespace == original
		for _, inode := range activeNamespaces {
			if namespace == fmt.Sprintf("net:[%d]", inode) {
				allowed = true
			}
		}
		if err == nil && !allowed {
			t.Fatalf("contaminated surviving task %s=%s", path, namespace)
		}
	}
	var unrelated sync.WaitGroup
	for range 128 {
		unrelated.Go(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			namespace, err := os.Readlink("/proc/thread-self/ns/net")
			if err != nil || namespace != original || unix.Gettid() == tid {
				t.Errorf("unrelated goroutine contaminated: tid=%d namespace=%s err=%v", unix.Gettid(), namespace, err)
			}
		})
	}
	unrelated.Wait()
}

func TestPhase36FixM0(t *testing.T) {
	requireFastpath(t)
	for range 3 {
		fixSubprocess(t, "TestPhase36FixM0", "SPLICORE_PHASE36_FIX_M0")
	}
}

func TestPhase36FixRestoreStress(t *testing.T) {
	requireFastpath(t)
	if fixSubprocess(t, "TestPhase36FixRestoreStress", "SPLICORE_PHASE36_FIX_RESTORE_CHILD") {
		return
	}
	original, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	baseline := fastHostState(t)
	for _, stage := range []string{"namespace-created", "rtnetlink", "control", "ingress-socket", "netfilter-open", "netfilter"} {
		t.Run(stage, func(t *testing.T) {
			runtime.GC()
			baseG := runtime.NumGoroutine()
			baseFD := fdCount()
			beforeTasks, _ := os.ReadDir("/proc/self/task")
			for i := range 100 {
				c := fastConfig(t)
				if i%2 == 0 {
					c.Backend = E.Auto
				}
				e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
				if err != nil {
					t.Fatal(err)
				}
				var k *kernelBackend
				var tid int
				var private string
				e.kernelFactory = func(e *Endpoint, c E.WireGuard) (WireGuardBackend, error) {
					raw, err := newKernelBackend(e, c)
					if err != nil {
						return nil, err
					}
					k = raw.(*kernelBackend)
					k.fault = func(step string) error {
						if step != stage {
							return nil
						}
						tid = unix.Gettid()
						private, _ = os.Readlink("/proc/thread-self/ns/net")
						return denyWorkerSyscall(unix.SYS_SETNS, unix.EPERM)
					}
					return raw, nil
				}
				err = e.Start(context.Background())
				if backendAvailability(err) != NamespaceRestoreFailure || !errors.Is(err, unix.EPERM) || fallbackEligible(err) || e.Status().Selected != "" || e.Status().Availability != NamespaceRestoreFailure || private == original {
					t.Fatalf("iteration %d stage %s err=%v status=%+v tid=%d", i, stage, err, e.Status(), tid)
				}
				assertWorkerGone(t, tid, original)
				if err = e.Close(); err != nil {
					t.Fatal(err)
				}
				if err = e.Close(); err != nil {
					t.Fatal(err)
				}
				if k.ns != -1 {
					t.Fatal("owned namespace FD survived rollback")
				}
				if _, err := netlink.LinkByName(k.name); err == nil {
					t.Fatal("owned birth interface survived rollback")
				}
				if i == 0 {
					t.Logf("worker_tid=%d original=%s private=%s discarded=true surviving_tasks=original", tid, original, private)
				}
			}
			runtime.GC()
			until := time.Now().Add(3 * time.Second)
			for runtime.NumGoroutine() > baseG && time.Now().Before(until) {
				runtime.Gosched()
				time.Sleep(time.Millisecond)
			}
			if runtime.NumGoroutine() > baseG {
				t.Fatalf("goroutine growth: %d -> %d", baseG, runtime.NumGoroutine())
			}
			if fdCount() != baseFD {
				t.Fatalf("FD growth: %d -> %d", baseFD, fdCount())
			}
			afterTasks, _ := os.ReadDir("/proc/self/task")
			if len(afterTasks) > len(beforeTasks)+16 {
				t.Fatalf("unbounded task growth: %d -> %d", len(beforeTasks), len(afterTasks))
			}
			t.Logf("100/100 restore failures; tasks=%d/%d FD=%d/%d goroutines=%d/%d unrelated_goroutines=12800 contaminated=0", len(beforeTasks), len(afterTasks), baseFD, fdCount(), baseG, runtime.NumGoroutine())
		})
	}
	if fastHostState(t) != baseline {
		t.Fatal("host routes/rules/DNS/firewall changed")
	}
}

func TestPhase36FixNamespaceMatrix(t *testing.T) {
	requireFastpath(t)
	if fixSubprocess(t, "TestPhase36FixNamespaceMatrix", "SPLICORE_PHASE36_FIX_MATRIX_CHILD") {
		return
	}
	config := fastConfig(t)
	config.Peers[0].Endpoint = "127.0.0.1:9" // a configured, nonresponding handshake target
	e := fastEndpoint(t, config, Options{})
	k := e.backend.(*kernelBackend)
	original, _ := os.Readlink("/proc/thread-self/ns/net")
	operationError := errors.New("operation sentinel")
	for _, mode := range []string{"entry", "operation", "operation-restore", "panic", "panic-restore", "cancel-before", "cancel-inside", "cancel-restore", "deadline", "deadline-restore", "socket-cancel", "socket-deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var deadlineCancel context.CancelFunc
			if mode == "deadline" || mode == "deadline-restore" || mode == "socket-deadline" {
				ctx, deadlineCancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer deadlineCancel()
			}
			if mode == "cancel-before" {
				cancel()
			}
			target := k.ns
			if mode == "entry" {
				target = 1 << 30
			}
			tid := 0
			err := namespaceRun(ctx, target, func() error {
				tid = unix.Gettid()
				if mode == "operation-restore" || mode == "panic-restore" || mode == "cancel-restore" || mode == "deadline-restore" {
					if err := denyWorkerSyscall(unix.SYS_SETNS, unix.EPERM); err != nil {
						return err
					}
				}
				switch mode {
				case "operation", "operation-restore":
					return operationError
				case "panic", "panic-restore":
					panic("test-only panic")
				case "cancel-inside", "cancel-restore":
					cancel()
				case "deadline", "deadline-restore":
					<-ctx.Done()
				case "socket-cancel", "socket-deadline":
					if mode == "socket-cancel" {
						stop := time.AfterFunc(5*time.Millisecond, cancel)
						defer stop.Stop()
					}
					conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", "10.36.0.2:1")
					if conn != nil {
						_ = conn.Close()
					}
					return err
				}
				return nil
			})
			if err == nil {
				t.Fatal("expected failure")
			}
			restore := mode == "operation-restore" || mode == "panic-restore" || mode == "cancel-restore" || mode == "deadline-restore"
			if restore {
				if backendAvailability(err) != NamespaceRestoreFailure || fallbackEligible(err) || !errors.Is(err, unix.EPERM) {
					t.Fatalf("restore classification: %v", err)
				}
				assertWorkerGone(t, tid, original)
			}
			if (mode == "operation" || mode == "operation-restore") && !errors.Is(err, operationError) {
				t.Fatal("operation cause lost")
			}
			if mode == "entry" && !errors.Is(err, unix.EBADF) {
				t.Fatal("entry errno lost")
			}
			if mode == "cancel-before" && tid != 0 {
				t.Fatal("canceled operation entered namespace")
			}
			if (mode == "deadline" || mode == "deadline-restore") && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline cause lost: %v", err)
			}
			if mode == "socket-deadline" {
				// net.Dialer and the context timer share a deadline. Either
				// the poller or context may expire first; both are valid.
				var timeout net.Error
				if !errors.Is(err, context.DeadlineExceeded) && (!errors.As(err, &timeout) || !timeout.Timeout()) {
					t.Fatalf("socket deadline cause lost: %v", err)
				}
			}
			if (mode == "cancel-inside" || mode == "cancel-restore" || mode == "cancel-before" || mode == "socket-cancel") && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel cause lost: %v", err)
			}
		})
	}
}

func TestPhase36FixFallbackMatrix(t *testing.T) {
	for _, class := range []Availability{UnsupportedPlatform, KernelUnavailable, InsufficientPrivilege, NetNSUnavailable, NetlinkUnavailable, NetfilterUnavailable, ConfigInvalid, RuntimeFailure, InterfaceCollision, CleanupFailure, NamespaceRestoreFailure} {
		t.Run(string(class), func(t *testing.T) {
			expected := class == UnsupportedPlatform || class == KernelUnavailable || class == InsufficientPrivilege || class == NetNSUnavailable || class == NetlinkUnavailable || class == NetfilterUnavailable
			base := &BackendError{Class: class, Operation: "test", Cause: unix.EPERM}
			if fallbackEligible(base) != expected || !errors.Is(base, unix.EPERM) {
				t.Fatal("classification mismatch")
			}
			var errno unix.Errno
			if !errors.As(base, &errno) || errno != unix.EPERM {
				t.Fatal("causal errno type lost")
			}
			for _, fatal := range []error{&BackendError{Class: NamespaceRestoreFailure, Cause: unix.EIO}, &BackendError{Class: CleanupFailure}, &BackendError{Class: RuntimeFailure}, context.Canceled, context.DeadlineExceeded, errors.New("corrupt state"), &resolutionError{cause: errors.New("Core DNS failure")}} {
				if fallbackEligible(errors.Join(base, fatal)) || fallbackEligible(errors.Join(fatal, base)) {
					t.Fatal("joined fatal error allowed fallback")
				}
			}
			joined := errors.Join(base, &BackendError{Class: NamespaceRestoreFailure, Cause: unix.EIO})
			if backendAvailability(joined) != NamespaceRestoreFailure || !errors.Is(joined, unix.EIO) {
				t.Fatal("restore failed to dominate")
			}
		})
	}
}

func TestPhase36FixLinkLocal(t *testing.T) {
	requireFastpath(t)
	for _, pairing := range [][2]E.WireGuardBackend{{E.Kernel, E.Kernel}, {E.Kernel, E.Userspace}, {E.Userspace, E.Kernel}, {E.Userspace, E.Userspace}, {E.Auto, E.Kernel}} {
		t.Run(string(pairing[0])+"-"+string(pairing[1]), func(t *testing.T) {
			ac, bc := fastConfig(t), fastConfig(t)
			ac.Backend, bc.Backend = pairing[0], pairing[1]
			ac.Addresses = []string{"fe80::1/128", "10.36.0.1/32", "fd36::1/128"}
			bc.Addresses = []string{"fe80::2/128", "10.36.0.2/32", "fd36::2/128"}
			ak, bk := wgtypes.Key(ac.PrivateKey.Reveal()), wgtypes.Key(bc.PrivateKey.Reveal())
			ac.Peers[0].PublicKey, bc.Peers[0].PublicKey = bk.PublicKey().String(), ak.PublicKey().String()
			ac.Peers[0].AllowedIPs, bc.Peers[0].AllowedIPs = bc.Addresses, ac.Addresses
			b := fastEndpoint(t, bc, Options{})
			ac.Peers[0].Endpoint = net.JoinHostPort("127.0.0.1", itoa(b.Status().ListenPort))
			a := fastEndpoint(t, ac, Options{})
			for _, e := range []*Endpoint{a, b} {
				if k, ok := e.backend.(*kernelBackend); ok {
					ll, err := indexedSockaddr(netip.MustParseAddrPort("[fe80::1]:0"), uint32(k.meta.InterfaceIndex))
					if err != nil || ll.ZoneId != uint32(k.meta.InterfaceIndex) {
						t.Fatal("wrong owned interface scope")
					}
					global, err := indexedSockaddr(netip.MustParseAddrPort("[fd36::1]:0"), uint32(k.meta.InterfaceIndex))
					if err != nil || global.ZoneId != 0 {
						t.Fatal("zone added to ULA")
					}
					addresses, err := k.links.AddrList(k.link, unix.AF_INET6)
					if err != nil || len(addresses) < 2 {
						t.Fatalf("address readback: %v %v", addresses, err)
					}
					routes, err := k.links.RouteList(k.link, unix.AF_INET6)
					found := false
					for _, route := range routes {
						if route.Dst != nil && route.Dst.IP.IsLinkLocalUnicast() && route.LinkIndex == k.meta.InterfaceIndex && (route.Scope == netlink.SCOPE_LINK || route.Scope == netlink.SCOPE_UNIVERSE) {
							found = true
							t.Logf("IPv6 route readback: %s scope=%d owned_ifindex=%d", route.String(), route.Scope, k.meta.InterfaceIndex)
						}
					}
					if err != nil || !found {
						t.Fatalf("link-local route missing: %v", err)
					}
				}
			}
			for i := range 100 {
				transferTCP(t, a, "fe80::2")
				transferUDP(t, a, "fe80::2", 64+i)
			}
			transferTCP(t, b, "fe80::1")
			transferUDP(t, b, "fe80::1", 512)
			for _, ip := range []string{"10.36.0.2", "fd36::2"} {
				transferTCP(t, a, ip)
				transferUDP(t, a, ip, 256)
			}
			t.Log("100 TCP + 100 UDP link-local exchanges; reverse and simultaneous IPv4/ULA PASS")
		})
	}
	if err := (&kernelBackend{}).withIPv6Scope(context.Background(), func(uint32) error { return nil }); backendAvailability(err) != RuntimeFailure {
		t.Fatal("missing scope not detected")
	}
}

func TestPhase36FixNetfilterUnavailable(t *testing.T) {
	requireFastpath(t)
	if fixSubprocess(t, "TestPhase36FixNetfilterUnavailable", "SPLICORE_PHASE36_FIX_NETFILTER_CHILD") {
		return
	}
	baseline := fastHostState(t)
	original, _ := os.Readlink("/proc/thread-self/ns/net")
	for _, mode := range []E.WireGuardBackend{E.Kernel, E.Auto} {
		t.Run(string(mode), func(t *testing.T) {
			for range 100 {
				c := fastConfig(t)
				c.Backend = mode
				e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
				if err != nil {
					t.Fatal(err)
				}
				var k *kernelBackend
				var tid int
				e.kernelFactory = func(e *Endpoint, c E.WireGuard) (WireGuardBackend, error) {
					raw, err := newKernelBackend(e, c)
					if err != nil {
						return nil, err
					}
					k = raw.(*kernelBackend)
					k.fault = func(stage string) error {
						if stage != "netfilter-before-open" {
							return nil
						}
						tid = unix.Gettid()
						// Retain an additional lock so a thread bearing the test's
						// seccomp policy is discarded even after a successful restore.
						runtime.LockOSThread()
						return denyNetfilterSocket()
					}
					return raw, nil
				}
				err = e.Start(context.Background())
				if mode == E.Kernel {
					if backendAvailability(err) != NetfilterUnavailable || !errors.Is(err, unix.EPROTONOSUPPORT) || e.Status().Selected != "" {
						t.Fatalf("explicit kernel: %v %+v", err, e.Status())
					}
				} else if err != nil || e.Status().Selected != E.Userspace || e.Status().Availability != NetfilterUnavailable {
					t.Fatalf("clean fallback: %v %+v", err, e.Status())
				}
				if k.ns != -1 {
					t.Fatal("fallback before cleanup")
				}
				until := time.Now().Add(time.Second)
				for !errors.Is(unix.Tgkill(os.Getpid(), tid, 0), unix.ESRCH) && time.Now().Before(until) {
					time.Sleep(time.Millisecond)
				}
				assertWorkerGone(t, tid, original)
				if err = e.Close(); err != nil {
					t.Fatal(err)
				}
				if err = e.Close(); err != nil {
					t.Fatal(err)
				}
			}
			t.Log("100/100 persistent EPROTONOSUPPORT: no panic; kernel explicit error / auto clean userspace fallback")
		})
	}
	if fastHostState(t) != baseline {
		t.Fatal("netfilter capability failures mutated host state")
	}
}

type fixFailCloser struct{ err error }

func (c fixFailCloser) Close() error { return c.err }

func TestPhase36FixCleanupErrors(t *testing.T) {
	requireFastpath(t)
	c := fastConfig(t)
	e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	raw, err := newKernelBackend(e, c)
	if err != nil {
		t.Fatal(err)
	}
	k := raw.(*kernelBackend)
	first, second := errors.New("first close failure"), errors.New("second close failure")
	for _, cause := range []error{first, second} {
		if _, err = k.owner.Track(k.recordCloser(fixFailCloser{cause})); err != nil {
			t.Fatal(err)
		}
	}
	err = k.Close()
	if !errors.Is(err, first) || !errors.Is(err, second) || backendAvailability(err) != CleanupFailure || fallbackEligible(err) {
		t.Fatalf("cleanup errors lost: %v", err)
	}
	if again := k.Close(); again != err {
		t.Fatal("Close result changed")
	}
	for _, mode := range []E.WireGuardBackend{E.Kernel, E.Auto} {
		c.Backend = mode
		nilEndpoint, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
		if err != nil {
			t.Fatal(err)
		}
		nilEndpoint.kernelFactory = func(*Endpoint, E.WireGuard) (WireGuardBackend, error) { return nil, nil }
		if err = nilEndpoint.Start(context.Background()); backendAvailability(err) != RuntimeFailure || nilEndpoint.Status().Selected != "" {
			t.Fatalf("nil dependency: %v", err)
		}
		closedStatus(t, nilEndpoint)
	}
}

func TestPhase36FixSocketRestore(t *testing.T) {
	requireFastpath(t)
	if fixSubprocess(t, "TestPhase36FixSocketRestore", "SPLICORE_PHASE36_FIX_SOCKET_CHILD") {
		return
	}
	a, b := fastPair(t, E.Kernel, E.Kernel, false, "127.0.0.1")
	k := a.backend.(*kernelBackend)
	original, _ := os.Readlink("/proc/thread-self/ns/net")
	for _, stage := range []string{"tcp-socket", "udp-socket"} {
		var tid int
		k.fault = func(step string) error {
			if step != stage {
				return nil
			}
			tid = unix.Gettid()
			return denyWorkerSyscall(unix.SYS_SETNS, unix.EPERM)
		}
		var err error
		if stage == "tcp-socket" {
			_, err = a.DialContext(context.Background(), access.Endpoint{Host: "10.36.0.2", Port: 12345})
		} else {
			_, err = a.ListenPacket(context.Background(), access.Endpoint{Host: "10.36.0.2", Port: 12346})
		}
		if backendAvailability(err) != NamespaceRestoreFailure || !errors.Is(err, unix.EPERM) {
			t.Fatalf("socket restore: %v", err)
		}
		assertWorkerGone(t, tid, original)
		k.fault = nil
		transferTCP(t, a, "10.36.0.2")
		transferUDP(t, b, "fd36::1", 64)
	}
}

func TestPhase36FixConcurrentIsolation(t *testing.T) {
	requireFastpath(t)
	if fixSubprocess(t, "TestPhase36FixConcurrentIsolation", "SPLICORE_PHASE36_FIX_ISOLATION_CHILD") {
		return
	}
	b, peer := fastPair(t, E.Kernel, E.Kernel, false, "127.0.0.1")
	u, up := fastPair(t, E.Userspace, E.Userspace, false, "127.0.0.1")
	base := b.Status()
	var work sync.WaitGroup
	work.Go(func() {
		for range 30 {
			transferTCP(t, b, "10.36.0.2")
			transferUDP(t, peer, "fd36::1", 128)
			_ = b.Status()
		}
	})
	work.Go(func() {
		for range 30 {
			transferTCP(t, u, "10.36.0.2")
			transferUDP(t, up, "fd36::1", 128)
			_ = u.Status()
		}
	})
	original, _ := os.Readlink("/proc/thread-self/ns/net")
	for range 30 {
		c := fastConfig(t)
		c.Backend = E.Auto
		e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
		if err != nil {
			t.Fatal(err)
		}
		var tid int
		e.kernelFactory = func(e *Endpoint, c E.WireGuard) (WireGuardBackend, error) {
			raw, err := newKernelBackend(e, c)
			if err != nil {
				return nil, err
			}
			k := raw.(*kernelBackend)
			k.fault = func(stage string) error {
				if stage != "netfilter" {
					return nil
				}
				tid = unix.Gettid()
				return denyWorkerSyscall(unix.SYS_SETNS, unix.EPERM)
			}
			return raw, nil
		}
		if err = e.Start(context.Background()); backendAvailability(err) != NamespaceRestoreFailure || e.Status().Selected != "" {
			t.Fatalf("failed A: %v", err)
		}
		assertWorkerGone(t, tid, original, base.Namespace, peer.Status().Namespace)
		closedStatus(t, e)
	}
	work.Wait()
	if after := b.Status(); after.Namespace != base.Namespace || after.InterfaceName != base.InterfaceName || after.State != Active || after.Selected != E.Kernel {
		t.Fatal("instance B corrupted")
	}
	t.Log("30 failing A instances alongside 30 kernel and 30 userspace TCP/UDP/snapshot cycles: PASS")
}

func TestPhase36FixOverlappingLinkLocal(t *testing.T) {
	requireFastpath(t)
	var endpoints []*Endpoint
	for instance := range 2 {
		ac, bc := fastConfig(t), fastConfig(t)
		ac.Tag, bc.Tag = fmt.Sprintf("overlap-a-%d", instance), fmt.Sprintf("overlap-b-%d", instance)
		ac.Addresses, bc.Addresses = []string{"fe80::1/128"}, []string{"fe80::2/128"}
		ak, bk := wgtypes.Key(ac.PrivateKey.Reveal()), wgtypes.Key(bc.PrivateKey.Reveal())
		ac.Peers[0].PublicKey, bc.Peers[0].PublicKey = bk.PublicKey().String(), ak.PublicKey().String()
		ac.Peers[0].AllowedIPs, bc.Peers[0].AllowedIPs = bc.Addresses, ac.Addresses
		b := fastEndpoint(t, bc, Options{})
		ac.Peers[0].Endpoint = net.JoinHostPort("127.0.0.1", itoa(b.Status().ListenPort))
		a := fastEndpoint(t, ac, Options{})
		endpoints = append(endpoints, a, b)
	}
	if endpoints[0].Status().Namespace == endpoints[2].Status().Namespace || endpoints[0].Status().InterfaceName == endpoints[2].Status().InterfaceName {
		t.Fatal("instances share ownership")
	}
	var work sync.WaitGroup
	for _, e := range []*Endpoint{endpoints[0], endpoints[2]} {
		work.Go(func() {
			for range 10 {
				transferTCP(t, e, "fe80::2")
				transferUDP(t, e, "fe80::2", 128)
			}
		})
	}
	work.Wait()
}

func TestPhase36FixOfficialLinkLocalInterop(t *testing.T) {
	requireFastpath(t)
	for _, pskEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("psk-%t", pskEnabled), func(t *testing.T) {
			private, public := testKeys(t)
			var secret E.Secret
			psk := ""
			if pskEnabled {
				secret, _ = testKeys(t)
				psk = E.EncodeKey(secret.Reveal())
			}
			o := startOracle(t, public, []string{"fe80::2"}, []string{"fe80::1/128"}, psk, 0)
			config := E.WireGuard{Backend: E.Kernel, Tag: "official-link-local", PrivateKey: private, Addresses: []string{"fe80::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: o.PublicKey, PreSharedKey: secret, Endpoint: net.JoinHostPort("127.0.0.1", itoa(o.ListenPort)), AllowedIPs: []string{"fe80::2/128"}}}}
			e := fastEndpoint(t, config, Options{})
			o.endpoint(t, e.Status().ListenPort)
			oracleTCP(t, e, "fe80::2")
			oracleUDP(t, e, "fe80::2")
			o.dial(t, "tcp", "fe80::1", false)
			o.dial(t, "udp", "fe80::1", false)
			if e.Status().Peers[0].LastHandshake.IsZero() {
				t.Fatal("official link-local handshake missing")
			}
		})
	}
}

func TestPhase36FixLinuxLinkLocalInterop(t *testing.T) {
	requireFastpath(t)
	wg := os.Getenv("SPLICORE_PHASE34_KERNEL_WG")
	if wg == "" {
		t.Skip("external Linux wg oracle not configured")
	}
	command := func(binary string, args ...string) {
		t.Helper()
		if out, err := exec.Command(binary, args...).CombinedOutput(); err != nil {
			t.Fatalf("kernel oracle command %s: %v %s", binary, err, out)
		}
	}
	command("ip", "link", "add", "phase36ll", "type", "wireguard")
	t.Cleanup(func() { command("ip", "link", "del", "phase36ll") })
	private, public := testKeys(t)
	remote, remotePublic := testKeys(t)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	if err = socket.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "private-key")
	if err = os.WriteFile(file, []byte(E.EncodeKey(remote.Reveal())), 0o600); err != nil {
		t.Fatal(err)
	}
	command(wg, "set", "phase36ll", "private-key", file, "listen-port", itoa(port), "peer", public, "allowed-ips", "fe80::1/128")
	command("ip", "-6", "addr", "add", "fe80::2/64", "dev", "phase36ll", "nodad")
	command("ip", "link", "set", "dev", "phase36ll", "mtu", "1420", "up")
	config := E.WireGuard{Backend: E.Kernel, Tag: "linux-link-local", PrivateKey: private, Addresses: []string{"fe80::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: remotePublic, Endpoint: net.JoinHostPort("127.0.0.1", itoa(port)), AllowedIPs: []string{"fe80::2/128"}}}}
	e := fastEndpoint(t, config, Options{})
	command(wg, "set", "phase36ll", "peer", public, "endpoint", net.JoinHostPort("127.0.0.1", itoa(e.Status().ListenPort)))
	link, err := netlink.LinkByName("phase36ll")
	if err != nil {
		t.Fatal(err)
	}
	zone := strconv.Itoa(link.Attrs().Index)
	xrayHostEcho(t, "fe80::2%"+zone)
	oracleTCP(t, e, "fe80::2")
	oracleUDP(t, e, "fe80::2")
	for _, network := range []string{"tcp6", "udp6"} {
		conn, err := net.DialTimeout(network, net.JoinHostPort("fe80::1%"+zone, "12345"), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := "independent Linux kernel link-local"
		if _, err = conn.Write([]byte(payload)); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		_, err = io.ReadFull(conn, got)
		_ = conn.Close()
		if err != nil || string(got) != payload {
			t.Fatalf("reverse %s: %v", network, err)
		}
	}
	if e.Status().Peers[0].LastHandshake.IsZero() {
		t.Fatal("Linux link-local handshake missing")
	}
}
