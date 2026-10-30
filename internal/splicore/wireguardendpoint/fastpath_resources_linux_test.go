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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func fastHostState(t *testing.T) string {
	t.Helper()
	var state []string
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		state = append(state, fmt.Sprintf("link %d %s %s %s", link.Attrs().Index, link.Attrs().Name, link.Type(), link.Attrs().Alias))
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		state = append(state, "route "+route.String())
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range rules {
			state = append(state, fmt.Sprintf("rule %d %s", family, rule.String()))
		}
	}
	dns, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	state = append(state, "dns "+string(dns))
	firewall, err := exec.Command("nft", "--json", "list", "ruleset").Output()
	if err != nil {
		t.Fatal(err)
	}
	state = append(state, "firewall "+string(firewall))
	sort.Strings(state)
	return strings.Join(state, "\n")
}

func TestPhase36HostIntegrity(t *testing.T) {
	requireFastpath(t)
	before := fastHostState(t)
	e := fastEndpoint(t, fastConfig(t), Options{})
	if fastHostState(t) != before {
		t.Fatal("host routes/rules/interfaces/DNS/firewall changed after activation")
	}
	closedStatus(t, e)
	if fastHostState(t) != before {
		t.Fatal("host state changed after Close")
	}
}

func TestPhase36LargePeerReadback(t *testing.T) {
	requireFastpath(t)
	c := fastConfig(t)
	c.Peers = nil
	for i := range 40 {
		_, key := testKeys(t)
		p := E.WireGuardPeer{PublicKey: key, PersistentKeepaliveInterval: i}
		if i%2 == 0 {
			p.PreSharedKey, _ = testKeys(t)
		}
		for j := range 64 {
			p.AllowedIPs = append(p.AllowedIPs, fmt.Sprintf("10.100.%d.%d/32", i, j))
		}
		c.Peers = append(c.Peers, p)
	}
	e := fastEndpoint(t, c, Options{})
	k := e.backend.(*kernelBackend)
	d, err := k.control.Device(k.name)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Peers) != 40 {
		t.Fatal("peer truncation")
	}
	for _, p := range d.Peers {
		if len(p.AllowedIPs) != 64 {
			t.Fatal("AllowedIPs truncation")
		}
	}
	key, _ := E.DecodeKey(c.Peers[0].PublicKey)
	keepalive := time.Duration(7) * time.Second
	update := wgtypes.PeerConfig{PublicKey: wgtypes.Key(key), UpdateOnly: true, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{ipNet(netip.MustParsePrefix("192.0.2.1/32"))}, PersistentKeepaliveInterval: &keepalive}
	if err = k.control.ConfigureDevice(k.name, wgtypes.Config{Peers: []wgtypes.PeerConfig{update}}); err != nil {
		t.Fatal(err)
	}
	if err = k.control.ConfigureDevice(k.name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: wgtypes.Key(key), Remove: true}}}); err != nil {
		t.Fatal(err)
	}
	d, err = k.control.Device(k.name)
	if err != nil || len(d.Peers) != 39 {
		t.Fatalf("peer removal %v", err)
	}
	t.Log("40 peers / 2560 AllowedIPs configured and read back; kernel peer update/removal succeeded")
}

func TestPhase36InterfaceCollision(t *testing.T) {
	requireFastpath(t)
	c := fastConfig(t)
	e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	raw, _ := newKernelBackend(e, c)
	k := raw.(*kernelBackend)
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: k.name, Alias: "unrelated"}}
	if err = netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(link)
	if err = netlink.LinkSetAlias(link, "unrelated"); err != nil {
		t.Fatal(err)
	}
	err = k.Prepare(context.Background())
	domain, ok := errors.AsType[*BackendError](err)
	if !ok || domain.Class != InterfaceCollision || !errors.Is(err, unix.EEXIST) {
		t.Fatalf("collision: %v", err)
	}
	if err = k.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := netlink.LinkByName(k.name)
	if err != nil || got.Type() != "dummy" || got.Attrs().Alias != "unrelated" {
		t.Fatalf("unrelated interface changed %v", err)
	}
}

func TestPhase36ListenPortCollision(t *testing.T) {
	requireFastpath(t)
	c := fastConfig(t)
	e := fastEndpoint(t, c, Options{})
	c.ListenPort = e.Status().ListenPort
	other, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	err = other.Start(context.Background())
	if !errors.Is(err, unix.EADDRINUSE) {
		t.Fatalf("lost collision errno %v", err)
	}
	closedStatus(t, other)
	if e.Status().State != Active {
		t.Fatal("other runtime disturbed")
	}
}

func TestPhase36CoreDNSKernel(t *testing.T) {
	requireFastpath(t)
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("system DNS forbidden")
	}}
	// Register first so every endpoint joins its workers before restoring the
	// process-wide resolver, which net.Dialer reads even for numeric targets.
	t.Cleanup(func() { net.DefaultResolver = previous })
	c := fastConfig(t)
	server := fastConfig(t)
	server.Addresses = []string{"10.36.0.2/32", "fd36::2/128"}
	clientKey := wgtypes.Key(c.PrivateKey.Reveal())
	server.Peers[0].PublicKey = clientKey.PublicKey().String()
	server.Peers[0].AllowedIPs = []string{"10.36.0.1/32", "fd36::1/128"}
	peer := fastEndpoint(t, server, Options{})
	serverKey := wgtypes.Key(server.PrivateKey.Reveal())
	c.Peers[0].PublicKey = serverKey.PublicKey().String()
	c.Peers[0].Endpoint = net.JoinHostPort("core-only.invalid", itoa(peer.Status().ListenPort))
	calls := 0
	e := fastEndpoint(t, c, Options{LookupEndpoint: func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}})
	k := e.backend.(*kernelBackend)
	d, err := k.control.Device(k.name)
	if err != nil || calls != 1 || d.Peers[0].Endpoint.String() != net.JoinHostPort("127.0.0.1", itoa(peer.Status().ListenPort)) {
		t.Fatalf("Core DNS calls=%d err=%v", calls, err)
	}
	transferTCP(t, e, "10.36.0.2")
	transferUDP(t, e, "fd36::2", 1024)
}

func TestPhase36SocketNamespace(t *testing.T) {
	requireFastpath(t)
	a, b := fastPair(t, E.Kernel, E.Kernel, false, "127.0.0.1")
	k := a.backend.(*kernelBackend)
	cookie := func(fd int) uint64 {
		v, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	host, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(host)
	hostCookie := cookie(host)
	var insideCookie uint64
	err = namespaceRun(context.Background(), k.ns, func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		insideCookie = cookie(fd)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if insideCookie == hostCookie {
		t.Fatal("namespace identity not isolated")
	}
	packet, err := k.ListenUDP(context.Background(), netip.MustParseAddr("10.36.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	// clientio owns the wrapper; exercise the raw kernel socket independently
	// in the same executor, then compare with a socket returned after restore.
	var returned *net.UDPConn
	err = namespaceRun(context.Background(), k.ns, func() error {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.36.0.1")})
		returned = c
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer returned.Close()
	raw, err := returned.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err = raw.Control(func(fd uintptr) {
		if cookie(int(fd)) != insideCookie {
			t.Error("returned socket left namespace")
		}
	}); err != nil {
		t.Fatal(err)
	}
	transferTCP(t, a, "10.36.0.2")
	transferUDP(t, b, "fd36::1", 1024)
	t.Logf("birth_inode=%d cleartext_inode=%d host_cookie=%d socket_cookie=%d cleartext_links=lo,wg", k.meta.BirthNamespace, k.meta.Namespace, hostCookie, insideCookie)
}

func TestPhase36ActiveClose(t *testing.T) {
	requireFastpath(t)
	a, b := fastPair(t, E.Kernel, E.Kernel, false, "127.0.0.1")
	c, err := a.DialContext(context.Background(), access.Endpoint{Host: "10.36.0.2", Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	reading := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); reading <- err }()
	closedStatus(t, a)
	closedStatus(t, b)
	select {
	case err := <-reading:
		if err == nil {
			t.Fatal("read outlived close")
		}
	case <-time.After(time.Second):
		t.Fatal("read stuck")
	}
	if a.Status().Selected != E.Kernel {
		t.Fatal("mid-session failover")
	}
}

func TestPhase36CrashCleanup(t *testing.T) {
	requireFastpath(t)
	// Cross-process activation/kill is orchestrated externally; this assertion
	// checks the anonymous namespace architecture has no named mount artifact.
	entries, err := os.ReadDir("/var/run/netns")
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "splicore") {
			t.Fatal("persistent namespace artifact")
		}
	}
}
