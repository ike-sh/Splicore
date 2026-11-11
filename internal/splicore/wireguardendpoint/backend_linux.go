//go:build linux

package wireguardendpoint

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type kernelBackend struct {
	e            *Endpoint
	config       E.WireGuard
	name, marker string
	ns           int
	birth, links *netlink.Handle
	link         netlink.Link
	moved        bool
	marked       bool
	control      *wgctrl.Client
	owner        *clientio.Owner
	workers      sync.WaitGroup
	once         sync.Once
	closeErr     error
	cleanupMu    sync.Mutex
	scopeMu      sync.RWMutex // Joins scoped I/O before link/namespace destruction.
	socketErrors error
	meta         BackendStatus
	ingressSlots chan struct{}
	// Test-only per-instance injection; never configured through public input.
	fault func(string) error
}

func interfaceName(instance []byte) string {
	h := sha256.Sum256(instance)
	return "spw" + hex.EncodeToString(h[:6])
}

func newKernelBackend(e *Endpoint, config E.WireGuard) (WireGuardBackend, error) {
	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		return nil, kernelError("instance identity", RuntimeFailure, err)
	}
	return &kernelBackend{e: e, config: config, name: interfaceName(instance[:]), marker: "splicore:" + hex.EncodeToString(instance[:]), ns: -1, owner: clientio.New(), ingressSlots: make(chan struct{}, 4096)}, nil
}

func (b *kernelBackend) step(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.fault != nil {
		return b.fault(name)
	}
	return nil
}

func (b *kernelBackend) Prepare(ctx context.Context) error {
	// This factory check keeps TUN protection verification authoritative. The
	// kernel transport uses the same bypass mark as Core's protected sockets.
	if _, err := b.e.options.Underlay.KernelTransportMark(ctx); err != nil {
		return err
	}
	var err error
	b.birth, err = netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return kernelError("birth rtnetlink", NetlinkUnavailable, err)
	}
	b.birth.SetSocketTimeout(3 * time.Second)
	var birthFD int
	birthFD, err = unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return kernelError("birth identity", NetNSUnavailable, err)
	}
	b.meta.BirthNamespace = namespaceInode(birthFD)
	if err = unix.Close(birthFD); err != nil {
		return cleanupError("birth namespace identity close", err)
	}
	if b.meta.BirthNamespace == 0 {
		return &BackendError{Class: RuntimeFailure, Operation: "birth namespace identity"}
	}
	err = namespaceRun(ctx, -1, func() error {
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return err
		}
		var err error
		b.ns, err = unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		return b.step(ctx, "namespace-created")
	})
	if err != nil {
		return kernelError("create namespace", NetNSUnavailable, err)
	}
	b.meta.Namespace = namespaceInode(b.ns)
	if b.meta.Namespace == 0 {
		return &BackendError{Class: RuntimeFailure, Operation: "private namespace identity"}
	}
	if err = b.step(ctx, "namespace"); err != nil {
		return err
	}
	err = namespaceRun(ctx, b.ns, func() error {
		var err error
		b.links, err = netlink.NewHandle(unix.NETLINK_ROUTE)
		if err != nil {
			return err
		}
		if b.links == nil {
			return &BackendError{Class: RuntimeFailure, Operation: "nil rtnetlink handle"}
		}
		return b.step(ctx, "rtnetlink")
	})
	if err != nil {
		return kernelError("target rtnetlink", NetlinkUnavailable, err)
	}
	b.links.SetSocketTimeout(3 * time.Second)
	// NLM_F_EXCL creation is the collision authority; no existing link is
	// ever adopted, reconfigured or deleted, even if its name looks familiar.
	attrs := netlink.NewLinkAttrs()
	attrs.Name, attrs.Alias, attrs.MTU = b.name, b.marker, b.config.InnerMTU()
	link := &netlink.GenericLink{LinkAttrs: attrs, LinkType: "wireguard"}
	if err = b.birth.LinkAdd(link); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return &BackendError{Class: InterfaceCollision, Operation: "create link", Cause: err}
		}
		return kernelError("create wireguard link", KernelUnavailable, err)
	}
	b.link = link
	if err = b.step(ctx, "link-created"); err != nil {
		return err
	}
	if err = b.birth.LinkSetAlias(b.link, b.marker); err != nil {
		return kernelError("mark birth link", RuntimeFailure, err)
	}
	if _, err = b.ownedLink(b.birth); err != nil {
		return err
	}
	b.marked = true
	if err = b.step(ctx, "link"); err != nil {
		return err
	}
	if err = b.birth.LinkSetNsFd(b.link, b.ns); err != nil {
		return kernelError("move link", NetNSUnavailable, err)
	}
	b.moved = true
	// Linux clears ifalias on a namespace move. Only the successfully created
	// link can enter our otherwise empty, exclusively owned target namespace.
	// Reapply the marker there before publishing it or accepting application I/O.
	b.link, err = b.links.LinkByName(b.name)
	if err != nil {
		return err
	}
	if b.link.Type() != "wireguard" {
		return &BackendError{Class: InterfaceCollision, Operation: "moved link type"}
	}
	if err = b.links.LinkSetAlias(b.link, b.marker); err != nil {
		return kernelError("mark moved link", RuntimeFailure, err)
	}
	b.link, err = b.ownedLink(b.links)
	if err != nil {
		return err
	}
	b.meta.InterfaceName, b.meta.InterfaceIndex = b.name, b.link.Attrs().Index
	if err = b.links.LinkSetMTU(b.link, b.config.InnerMTU()); err != nil {
		return kernelError("set inner MTU", RuntimeFailure, err)
	}
	return b.step(ctx, "move")
}

func (b *kernelBackend) ownedLink(h *netlink.Handle) (netlink.Link, error) {
	l, err := h.LinkByName(b.name)
	if err != nil {
		return nil, err
	}
	if l.Type() != "wireguard" || l.Attrs().Alias != b.marker {
		return nil, &BackendError{Class: InterfaceCollision, Operation: "ownership readback", Cause: fmt.Errorf("type=%s alias=%q expected=%q", l.Type(), l.Attrs().Alias, b.marker)}
	}
	return l, nil
}

func (b *kernelBackend) Start(ctx context.Context) error {
	if err := b.step(ctx, "start"); err != nil {
		return err
	}
	err := namespaceRun(ctx, b.ns, func() error {
		var err error
		b.control, err = wgctrl.New()
		if err != nil {
			return err
		}
		if b.control == nil {
			return &BackendError{Class: RuntimeFailure, Operation: "nil wireguard control"}
		}
		return b.step(ctx, "control")
	})
	if err != nil {
		return kernelError("wireguard generic netlink", NetlinkUnavailable, err)
	}
	key := wgtypes.Key(b.config.PrivateKey.Reveal())
	underlayMark, err := b.e.options.Underlay.KernelTransportMark(ctx)
	if err != nil {
		return err
	}
	port, mark := b.config.ListenPort, int(underlayMark)
	cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &port, FirewallMark: &mark, ReplacePeers: true}
	for _, peer := range b.config.Peers {
		public, _ := E.DecodeKey(peer.PublicKey)
		keepalive := time.Duration(peer.PersistentKeepaliveInterval) * time.Second
		p := wgtypes.PeerConfig{PublicKey: wgtypes.Key(public), ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &keepalive}
		if peer.PreSharedKey.Present() {
			psk := wgtypes.Key(peer.PreSharedKey.Reveal())
			p.PresharedKey = &psk
		}
		if peer.Endpoint != "" {
			p.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort(peer.Endpoint))
		}
		for _, raw := range peer.AllowedIPs {
			prefix := netip.MustParsePrefix(raw).Masked()
			p.AllowedIPs = append(p.AllowedIPs, ipNet(prefix))
		}
		cfg.Peers = append(cfg.Peers, p)
	}
	if err = b.control.ConfigureDevice(b.name, cfg); err != nil {
		return kernelError("configure wireguard", RuntimeFailure, err)
	}
	if err = b.step(ctx, "configure"); err != nil {
		return err
	}
	lo, err := b.links.LinkByName("lo")
	if err != nil {
		return kernelError("find loopback", RuntimeFailure, err)
	}
	if err = b.links.LinkSetUp(lo); err != nil {
		return kernelError("loopback up", RuntimeFailure, err)
	}
	if err = b.step(ctx, "loopback"); err != nil {
		return err
	}
	for _, raw := range b.config.Addresses {
		p := netip.MustParsePrefix(raw)
		address := &netlink.Addr{IPNet: ptrIPNet(p), Flags: unix.IFA_F_NODAD | unix.IFA_F_NOPREFIXROUTE}
		if err = b.links.AddrAdd(b.link, address); err != nil {
			return kernelError("assign address", RuntimeFailure, err)
		}
		if err = b.step(ctx, "address"); err != nil {
			return err
		}
	}
	if err = b.links.LinkSetUp(b.link); err != nil {
		return kernelError("link up", RuntimeFailure, err)
	}
	for _, peer := range cfg.Peers {
		for _, p := range peer.AllowedIPs {
			if err = b.links.RouteAdd(&netlink.Route{LinkIndex: b.link.Attrs().Index, Dst: &p, Scope: netlink.SCOPE_LINK}); err != nil {
				return kernelError("allowed route", RuntimeFailure, err)
			}
			if err = b.step(ctx, "route"); err != nil {
				return err
			}
		}
	}
	device, err := b.control.Device(b.name)
	if err != nil {
		return kernelError("readback wireguard", RuntimeFailure, err)
	}
	if err = verifyKernelDevice(device, cfg); err != nil {
		return err
	}
	b.meta.FWMark = mark
	if err = b.startIngress(ctx, lo); err != nil {
		return err
	}
	return b.step(ctx, "active")
}

func ipNet(p netip.Prefix) net.IPNet {
	return net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
func ptrIPNet(p netip.Prefix) *net.IPNet { n := ipNet(p); return &n }

// These numeric, family-specific operations create sockets on the pinned
// calling thread; no resolver or happy-eyeballs worker can create a host socket.
func (b *kernelBackend) DialTCP(ctx context.Context, local netip.Addr, remote netip.AddrPort) (net.Conn, error) {
	ctx, done, err := b.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	var c net.Conn
	if local.IsLinkLocalUnicast() || remote.Addr().IsLinkLocalUnicast() {
		err = b.withIPv6Scope(ctx, func(index uint32) error {
			var err error
			c, err = dialIndexedIPv6(ctx, netip.AddrPortFrom(local, 0), remote, index, unix.SOCK_STREAM, false)
			if err != nil {
				return err
			}
			return b.step(ctx, "tcp-socket")
		})
	} else {
		err = namespaceRun(ctx, b.ns, func() error {
			var err error
			c, err = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(local.AsSlice())}}).DialContext(ctx, family("tcp", local), remote.String())
			if err != nil {
				return err
			}
			return b.step(ctx, "tcp-socket")
		})
	}
	if err != nil {
		if c != nil {
			err = errors.Join(err, cleanupError("failed TCP socket close", c.Close()))
		}
		return nil, kernelError("namespace TCP socket", RuntimeFailure, err)
	}
	return b.ownConn(c)
}

func socketOptions(transparent, original bool) func(string, string, syscall.RawConn) error {
	return func(network, _ string, raw syscall.RawConn) error {
		var err error
		e := raw.Control(func(fd uintptr) {
			level, option, orig := unix.SOL_IP, unix.IP_TRANSPARENT, unix.IP_RECVORIGDSTADDR
			if network == "tcp6" || network == "udp6" {
				level, option, orig = unix.SOL_IPV6, unix.IPV6_TRANSPARENT, unix.IPV6_RECVORIGDSTADDR
			}
			if transparent {
				err = unix.SetsockoptInt(int(fd), level, option, 1)
				if err == nil {
					err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}
			}
			if err == nil && original {
				err = unix.SetsockoptInt(int(fd), level, orig, 1)
			}
		})
		return errors.Join(e, err)
	}
}

func verifyKernelDevice(device *wgtypes.Device, cfg wgtypes.Config) error {
	invalid := &BackendError{Class: RuntimeFailure, Operation: "wireguard readback invariant"}
	if device.Type != wgtypes.LinuxKernel || device.PublicKey != cfg.PrivateKey.PublicKey() || device.ListenPort == 0 || (*cfg.ListenPort != 0 && device.ListenPort != *cfg.ListenPort) || device.FirewallMark != *cfg.FirewallMark || len(device.Peers) != len(cfg.Peers) {
		return invalid
	}
	peers := make(map[wgtypes.Key]wgtypes.PeerConfig, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		peers[peer.PublicKey] = peer
	}
	for _, actual := range device.Peers {
		want, ok := peers[actual.PublicKey]
		if !ok || actual.PersistentKeepaliveInterval != *want.PersistentKeepaliveInterval || len(actual.AllowedIPs) != len(want.AllowedIPs) {
			return invalid
		}
		if want.PresharedKey != nil && actual.PresharedKey != *want.PresharedKey {
			return invalid
		}
		if want.PresharedKey == nil && actual.PresharedKey != (wgtypes.Key{}) {
			return invalid
		}
		if want.Endpoint != nil && (actual.Endpoint == nil || actual.Endpoint.String() != want.Endpoint.String()) {
			return invalid
		}
		allowed := make(map[string]bool, len(want.AllowedIPs))
		for _, ip := range want.AllowedIPs {
			allowed[ip.String()] = true
		}
		for _, ip := range actual.AllowedIPs {
			if !allowed[ip.String()] {
				return invalid
			}
		}
		delete(peers, actual.PublicKey)
	}
	if len(peers) != 0 {
		return invalid
	}
	return nil
}

func family(network string, local netip.Addr) string {
	if local.Is4() {
		return network + "4"
	}
	return network + "6"
}

func (b *kernelBackend) ListenUDP(ctx context.Context, local netip.Addr) (net.PacketConn, error) {
	ctx, done, err := b.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	var c net.PacketConn
	if local.IsLinkLocalUnicast() {
		err = b.withIPv6Scope(ctx, func(index uint32) error {
			var err error
			c, err = listenIndexedIPv6(netip.AddrPortFrom(local, 0), index)
			if err != nil {
				return err
			}
			return b.step(ctx, "udp-socket")
		})
	} else {
		err = namespaceRun(ctx, b.ns, func() error {
			var err error
			c, err = (&net.ListenConfig{Control: socketOptions(false, false)}).ListenPacket(ctx, family("udp", local), net.JoinHostPort(local.String(), "0"))
			if err != nil {
				return err
			}
			return b.step(ctx, "udp-socket")
		})
	}
	if err != nil {
		if c != nil {
			err = errors.Join(err, cleanupError("failed UDP socket close", c.Close()))
		}
		return nil, kernelError("namespace UDP socket", RuntimeFailure, err)
	}
	return b.ownPacket(&scopedPacket{PacketConn: c, backend: b})
}

func (b *kernelBackend) Status(s *Status) {
	s.InterfaceName, s.InterfaceIndex, s.Namespace, s.BirthNamespace, s.FWMark = b.meta.InterfaceName, b.meta.InterfaceIndex, b.meta.Namespace, b.meta.BirthNamespace, b.meta.FWMark
	if b.control == nil {
		return
	}
	d, err := b.control.Device(b.name)
	if err != nil {
		return
	}
	s.ListenPort = d.ListenPort
	for i := range s.Peers {
		for _, p := range d.Peers {
			if s.Peers[i].PublicKey != p.PublicKey.String() {
				continue
			}
			s.Peers[i].LastHandshake = p.LastHandshakeTime
			s.Peers[i].RXBytes, s.Peers[i].TXBytes = uint64(p.ReceiveBytes), uint64(p.TransmitBytes)
			if p.Endpoint != nil {
				s.Peers[i].CurrentEndpoint = p.Endpoint.String()
			}
		}
	}
}

func (b *kernelBackend) Close() error {
	b.once.Do(func() {
		b.owner.Close()
		b.workers.Wait()
		b.scopeMu.Lock()
		defer b.scopeMu.Unlock()
		b.cleanupMu.Lock()
		b.closeErr = errors.Join(b.closeErr, b.socketErrors)
		b.cleanupMu.Unlock()
		if b.control != nil {
			b.closeErr = errors.Join(b.closeErr, cleanupError("wireguard control close", b.control.Close()))
			b.control = nil
		}
		if b.link != nil {
			h := b.birth
			if b.moved {
				h = b.links
			}
			owned, err := b.ownedLink(h)
			// Before the initial alias operation succeeds, the successful
			// exclusive create and its returned index prove ownership. Never
			// use this exception for a pre-existing or already marked link.
			if err != nil && !b.moved && !b.marked && b.link.Attrs().Index > 0 {
				created, lookup := h.LinkByIndex(b.link.Attrs().Index)
				if lookup == nil && created.Type() == "wireguard" && created.Attrs().Name == b.name && created.Attrs().Alias == "" {
					owned, err = created, nil
				}
			}
			if err == nil {
				err = h.LinkDel(owned)
			}
			b.closeErr = errors.Join(b.closeErr, cleanupError("owned link delete", err))
			if err == nil {
				b.link = nil
			}
		}
		if b.links != nil {
			b.links.Close()
			b.links = nil
		}
		if b.birth != nil {
			b.birth.Close()
			b.birth = nil
		}
		if b.ns >= 0 {
			b.closeErr = errors.Join(b.closeErr, cleanupError("private namespace close", unix.Close(b.ns)))
			b.ns = -1
		}
	})
	return b.closeErr
}
