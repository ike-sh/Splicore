//go:build linux && with_gvisor

package amneziawgendpoint

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	WG "github.com/ike-sh/Splicore/internal/splicore/wireguardendpoint"
	"github.com/mdlayher/genetlink"
	NL "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func backendConfig(t *testing.T, mode E.AmneziaWGBackend) E.AmneziaWG {
	private, _ := testKeys(t)
	_, pub := testKeys(t)
	return E.AmneziaWG{Protocol: "amneziawg", Version: "3.1", Backend: mode, Tag: "backend", PrivateKey: private, Addresses: []string{"10.37.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: pub, AllowedIPs: []string{"10.37.0.2/32"}}}}
}

func TestAWGKernelUnavailableAndAuto(t *testing.T) {
	if _, err := os.Stat("/sys/module/amneziawg"); err == nil {
		t.Skip("negative environment requires absent AWG module")
	}
	for _, mode := range []E.AmneziaWGBackend{E.AWGKernel, E.AWGAuto} {
		t.Run(string(mode), func(t *testing.T) {
			e, err := New(context.Background(), backendConfig(t, mode), Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			err = e.Start(context.Background())
			s := e.Status()
			if s.Availability != KernelUnavailable || s.InterfaceName != "" || s.InterfaceIndex != 0 || s.Namespace != 0 {
				t.Fatalf("wrong unavailable classification or partial state: %+v", s)
			}
			if mode == E.AWGKernel {
				if err == nil || s.Selected != "" {
					t.Fatal("explicit kernel fell back")
				}
			} else if err != nil || s.Selected != E.AWGUserspace || s.Protocol != "amneziawg" {
				t.Fatal("auto did not cleanly select AWG userspace")
			}
		})
	}
}

type injectedBackend struct {
	failure, cleanup error
	closed           bool
}

func (b *injectedBackend) Prepare(context.Context) error { return b.failure }
func (*injectedBackend) Start(context.Context) error     { return nil }
func (*injectedBackend) DialTCP(context.Context, netip.Addr, netip.AddrPort) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (*injectedBackend) ListenUDP(context.Context, netip.Addr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}
func (*injectedBackend) Status(*Status) {}
func (b *injectedBackend) Close() error { b.closed = true; return b.cleanup }
func TestAWGAutoFaultInjection(t *testing.T) {
	for _, class := range []Availability{KernelUnavailable, NetlinkUnavailable, InsufficientPrivilege, NetNSUnavailable, NetfilterUnavailable, NamespaceRestoreFailure, ConfigInvalid, RuntimeFailure, InterfaceCollision, CleanupFailure} {
		for _, cleanupFail := range []bool{false, true} {
			t.Run(string(class)+"/cleanup-"+map[bool]string{true: "fail", false: "ok"}[cleanupFail], func(t *testing.T) {
				e, err := New(context.Background(), backendConfig(t, E.AWGAuto), Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
				if err != nil {
					t.Fatal(err)
				}
				b := &injectedBackend{failure: &BackendError{Class: class, Operation: "injected prepare"}}
				if cleanupFail {
					b.cleanup = errors.New("injected cleanup")
				}
				e.kernelFactory = func(*Endpoint, E.AmneziaWG) (AmneziaWGBackend, error) { return b, nil }
				err = e.Start(context.Background())
				allowed := fallbackEligible(b.failure) && !cleanupFail
				if !b.closed || (err == nil) != allowed || (e.Status().Selected == E.AWGUserspace) != allowed {
					t.Fatal("fallback/rollback ordering")
				}
				_ = e.Close()
			})
		}
	}
	raw := errors.New("unclassified failure")
	if fallbackEligible(errors.Join(&BackendError{Class: KernelUnavailable}, raw)) {
		t.Fatal("raw sibling authorized fallback")
	}
	err := translateNamespaceError(errors.Join(&WG.BackendError{Class: WG.NamespaceRestoreFailure}, unix.EPERM))
	if backendAvailability(err) != NamespaceRestoreFailure || fallbackEligible(err) {
		t.Fatal("shared namespace fatal classification lost")
	}
}

func TestAWGNativeV3Encoding(t *testing.T) {
	c := qualificationProfile("I")
	c.H4 = &E.AWGRange{Min: 0xfffffff0, Max: 0xffffffff}
	attrs := obfuscationAttrs(c, false)
	m := map[uint16][]byte{}
	for _, a := range attrs {
		m[a.Type] = a.Data
	}
	if len(m[17]) != 8 || binary.NativeEndian.Uint64(m[17]) != 0xfffffffffffffff0 {
		t.Fatal("H range must use official native u64 v3 layout")
	}
	if binary.NativeEndian.Uint32(m[27]) != (19<<16|5) || len(m[33]) != 1 || m[34][0] != 1 || len(m[26]) != 32 {
		t.Fatal("AWG 3.1 attribute layout")
	}
	port, mark := 1234, 500
	key := wgtypes.Key([32]byte{1})
	cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &port, FirewallMark: &mark}
	raw, err := encodeDevice("spa123", c, cfg)
	if err != nil || len(raw) > 60000 {
		t.Fatal(err)
	}
	a, err := attrsMap(raw)
	if err != nil || binary.NativeEndian.Uint32(a[5]) != 1 {
		t.Fatal("replace peers flag")
	}
	p := wgtypes.PeerConfig{PublicKey: key, PersistentKeepaliveInterval: new(2 * time.Second), ReplaceAllowedIPs: true, Endpoint: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[::1]:1234"))}
	p.AllowedIPs = []net.IPNet{ipNet(netip.MustParsePrefix("10.37.0.0/24")), ipNet(netip.MustParsePrefix("fd37::/64"))}
	raw, err = encodePeer("spa123", p, true, p.AllowedIPs)
	if err != nil {
		t.Fatal(err)
	}
	a, _ = attrsMap(raw)
	nested, _ := NL.UnmarshalAttributes(a[8])
	decoded, err := decodePeer(nested[0].Data)
	if err != nil || decoded.PersistentKeepaliveInterval != 2*time.Second || decoded.Endpoint.String() != "[::1]:1234" || len(decoded.AllowedIPs) != 2 {
		t.Fatal("native peer grammar", err)
	}
	if verifyObfuscation(m, c) != nil {
		t.Fatal("complete feature readback rejected")
	}
	delete(m, 33)
	if verifyObfuscation(m, c) == nil {
		t.Fatal("missing RT feature falsely supported")
	}
	for _, raw := range [][]byte{{1, 2, 3}, make([]byte, 65537), {3, 0, 1, 0}} {
		if _, e := attrsMap(raw); e == nil {
			t.Fatal("malformed native attrs accepted")
		}
	}
}

func TestAWGNamespaceSharedExecutor(t *testing.T) {
	before := namespaceInode(openNS(t))
	err := namespaceRun(context.Background(), -1, func() error { return unix.Unshare(unix.CLONE_NEWNET) })
	if err != nil {
		t.Fatal(err)
	}
	after := namespaceInode(openNS(t))
	if before != after {
		t.Fatal("calling namespace changed")
	}
}

func openNS(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func FuzzAWGNativeAttributes(f *testing.F) {
	f.Add([]byte{4, 0, 2, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		_, _ = attrsMap(b)
		_, _ = decodePeer(b)
		_, _ = decodeSockaddr(b)
		if len(b) >= 8 {
			// Fuzz typed encoding as well as arbitrary decoder framing. This is
			// control-plane evidence and never invokes a netlink socket.
			c := E.AmneziaWG{Jc: uint16(b[0]), S4: binary.LittleEndian.Uint16(b[1:3]), ContentPaddingAddition: E.AWGRange{Min: uint32(b[3]), Max: uint32(b[3])}}
			c.H1 = &E.AWGRange{Min: binary.LittleEndian.Uint32(b[4:]), Max: binary.LittleEndian.Uint32(b[4:])}
			attrs := obfuscationAttrs(c, false)
			raw, err := NL.MarshalAttributes(attrs)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := attrsMap(raw)
			if err != nil || verifyObfuscation(actual, c) != nil {
				t.Fatal("native encoding round trip", err)
			}
		}
	})
}

// Fake generic-netlink responses are protocol/fault tests, never kernel runtime evidence.
type fakeGenl struct {
	data     []byte
	failure  error
	commands []uint8
	echoSet  bool
}

func (f *fakeGenl) Close() error                { return nil }
func (f *fakeGenl) SetDeadline(time.Time) error { return nil }
func (f *fakeGenl) Execute(m genetlink.Message, _ uint16, _ NL.HeaderFlags) ([]genetlink.Message, error) {
	f.commands = append(f.commands, m.Header.Command)
	if f.failure != nil {
		return nil, f.failure
	}
	if f.echoSet && m.Header.Command == 1 {
		f.data = append([]byte(nil), m.Data...)
	}
	return []genetlink.Message{{Header: genetlink.Header{Version: 3}, Data: f.data}}, nil
}

func TestAWGNativeCPSCanonical(t *testing.T) {
	for _, c := range []struct{ input, want string }{
		{"<b 0102><t><r 0><rc 3><rd 4>", "<b 0x0102><t><r 0><rc 3><rd 4>"},
		{"<b 0xABCD>  <dz 2><d><ds>", "<b 0xabcd><b 0x0000>"},
		{"<dz 0><d><ds>", "<r 0>"},
		{"", ""},
	} {
		if _, err := E.ParseCPS(c.input); err != nil {
			t.Fatal(err)
		}
		if got := nativeCPS(c.input); got != c.want {
			t.Fatalf("kernel CPS canonical encoding %q != %q", got, c.want)
		}
	}
}

// This fake exercises link ownership and mandatory disposal; it does not
// implement AWG packet processing and provides no kernel runtime evidence.
type probeLinksFake struct {
	link                              netlink.Link
	addError, aliasError, deleteError error
	clearAlias                        bool
	deleted                           bool
}

func (f *probeLinksFake) LinkAdd(l netlink.Link) error {
	if f.addError != nil {
		return f.addError
	}
	l.Attrs().Index = 77
	f.link = l
	return nil
}

func (f *probeLinksFake) LinkSetAlias(l netlink.Link, alias string) error {
	if f.aliasError != nil {
		l.Attrs().Alias = ""
		return f.aliasError
	}
	l.Attrs().Alias = alias
	return nil
}

func (f *probeLinksFake) LinkByIndex(int) (netlink.Link, error) {
	if f.clearAlias {
		f.link.Attrs().Alias = ""
	}
	return f.link, nil
}

func (f *probeLinksFake) LinkDel(netlink.Link) error {
	if f.deleteError != nil {
		return f.deleteError
	}
	f.deleted = true
	return nil
}

func TestAWGFeatureProbeDisposalFaults(t *testing.T) {
	for _, mode := range []string{"success", "ignored-attributes", "rejected-attributes", "collision", "initial-alias", "alias-lost", "delete-failure"} {
		t.Run(mode, func(t *testing.T) {
			links := &probeLinksFake{}
			wire := &fakeGenl{echoSet: true}
			b := &kernelBackend{name: "spa0123456789ab", marker: "splicore:test", ns: -1, probeLinks: links, control: &nativeControl{conn: wire}}
			switch mode {
			case "ignored-attributes":
				wire.echoSet = false
			case "rejected-attributes":
				wire.failure = unix.EOPNOTSUPP
			case "collision":
				links.addError = unix.EEXIST
			case "initial-alias":
				links.aliasError = unix.EIO
			case "alias-lost":
				links.clearAlias = true
			case "delete-failure":
				links.deleteError = unix.EIO
			}
			err := b.featureProbe(context.Background())
			if mode == "success" {
				if err != nil || !links.deleted || b.probeLink != nil {
					t.Fatal("probe did not dispose before success", err)
				}
				return
			}
			if err == nil {
				t.Fatal("probe fault accepted")
			}
			expectFallback := mode == "ignored-attributes" || mode == "rejected-attributes"
			if fallbackEligible(err) != expectFallback {
				t.Fatal("wrong probe fallback class", err)
			}
			expectDelete := expectFallback || mode == "initial-alias"
			if links.deleted != expectDelete {
				t.Fatal("foreign or incomplete probe disposal")
			}
			if (mode == "alias-lost" || mode == "delete-failure") && backendAvailability(err) != CleanupFailure {
				t.Fatal("disposal failure must be fatal", err)
			}
		})
	}
}

func TestAWGNativeReadAndTransportFaults(t *testing.T) {
	port := attr16(6, 1234)
	mark := attr32(7, 99)
	raw, _ := NL.MarshalAttributes([]NL.Attribute{attrString(2, "spa123"), port, mark, attrBytes(4, make([]byte, 32))})
	fake := &fakeGenl{data: raw}
	control := &nativeControl{conn: fake, family: genetlink.Family{ID: 42, Version: 3}}
	d, err := control.Device("spa123")
	if err != nil || d.ListenPort != 1234 || d.FirewallMark != 99 || len(fake.commands) != 1 || fake.commands[0] != 0 {
		t.Fatal("native GET grammar", err)
	}
	for _, errno := range []error{unix.EINVAL, unix.EOPNOTSUPP, unix.EPERM, unix.EIO} {
		fake.failure = errno
		if _, err = control.Device("spa123"); !errors.Is(err, errno) {
			t.Fatal("native errno identity lost")
		}
	}
	fake.failure = nil
	fake.data = []byte{1, 2, 3}
	if _, err = control.Device("spa123"); err == nil {
		t.Fatal("malformed dump accepted")
	}
	fake.data = raw
	if err = control.probe("spa123"); err == nil || !fallbackEligible(err) || backendAvailability(err) != KernelUnavailable {
		t.Fatal("silently ignored attributes did not classify as unavailable", err)
	}
	if control.Close() != nil {
		t.Fatal("control close")
	}
}

func TestAWGPrelinkNamespaceRollbackFaults(t *testing.T) {
	for _, stage := range []string{"namespace-created", "namespace", "rtnetlink", "before-link"} {
		t.Run(stage, func(t *testing.T) {
			c := backendConfig(t, E.AWGKernel)
			e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			raw, err := newKernelBackend(e, c)
			if err != nil {
				t.Fatal(err)
			}
			b := raw.(*kernelBackend)
			// Inject module availability only to exercise real prelink resources. The
			// fault always fires before LinkAdd; no unknown-link autoload is attempted.
			b.moduleCheck = func(context.Context) error { return nil }
			injected := errors.New("prelink injected fault")
			reached := false
			b.fault = func(s string) error {
				if s == stage {
					reached = true
					return injected
				}
				return nil
			}
			before := namespaceInode(openNS(t))
			if err = b.Prepare(context.Background()); !errors.Is(err, injected) || !reached {
				t.Fatal("fault not reached", err)
			}
			if b.link != nil {
				t.Fatal("prelink fault created an interface")
			}
			if err = b.Close(); err != nil {
				t.Fatal(err)
			}
			if b.ns != -1 || b.birth != nil || b.links != nil || namespaceInode(openNS(t)) != before {
				t.Fatal("partial namespace state survived rollback")
			}
		})
	}
}
