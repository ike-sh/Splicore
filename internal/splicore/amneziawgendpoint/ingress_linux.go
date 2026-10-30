//go:build linux

package amneziawgendpoint

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	nftnetlink "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Ingress uses only private-namespace rules. TPROXY preserves arbitrary original
// destinations and the kernel TCP/UDP stack, matching Core's L3 endpoint
// dispatcher contract. No nft/ip executable or host firewall rule is involved.
func (b *kernelBackend) startIngress(ctx context.Context, lo netlink.Link) (result error) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		prefix := "0.0.0.0/0"
		if family == unix.AF_INET6 {
			prefix = "::/0"
		}
		if err := b.links.RouteAdd(&netlink.Route{LinkIndex: lo.Attrs().Index, Dst: ptrIPNet(netip.MustParsePrefix(prefix)), Table: 100, Type: unix.RTN_LOCAL, Scope: netlink.SCOPE_HOST}); err != nil {
			return kernelError("private local route", RuntimeFailure, err)
		}
		rule := netlink.NewRule()
		rule.Family, rule.Table, rule.Priority, rule.Mark = family, 100, 100, 1
		mask := uint32(1)
		rule.Mask = &mask
		if err := b.links.RuleAdd(rule); err != nil {
			return kernelError("private ingress rule", RuntimeFailure, err)
		}
	}
	// Open in our worker with NetNS=0. The lasting socket preserves creation
	// errors and lets the safe caller explicitly close it, even on restore failure.
	var conn *nftables.Conn
	err := namespaceRun(ctx, b.ns, func() error {
		if err := b.step(ctx, "netfilter-before-open"); err != nil {
			return err
		}
		var err error
		conn, err = nftables.New(nftables.AsLasting(), nftables.WithSockOptions(func(c *nftnetlink.Conn) error {
			return c.SetDeadline(time.Now().Add(3 * time.Second))
		}))
		if err != nil {
			return err
		}
		if conn == nil {
			return &BackendError{Class: RuntimeFailure, Operation: "nil netfilter connection"}
		}
		return b.step(ctx, "netfilter-open")
	})
	if conn != nil {
		defer func() { result = errors.Join(result, cleanupError("netfilter close", conn.CloseLasting())) }()
	}
	if err != nil {
		return kernelError("private netfilter", NetfilterUnavailable, err)
	}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "splicore"})
	chain := conn.AddChain(&nftables.Chain{Table: table, Name: "ingress", Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle})
	iif := func() []expr.Any {
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(b.name), 0)}}
	}
	// Replies to locally originated Core sockets bypass ingress conversion.
	// Direction, rather than merely ESTABLISHED state, keeps subsequent
	// inbound request packets on their original transparent listener/flow.
	rules := iif()
	rules = append(rules, &expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, &expr.Verdict{Kind: expr.VerdictAccept})
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: rules})
	for _, v6 := range []bool{false, true} {
		local := netip.IPv4Unspecified()
		if v6 {
			local = netip.IPv6Unspecified()
		}
		for _, protocol := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			port, err := b.ingressSocket(ctx, local, protocol)
			if err != nil {
				return err
			}
			if err = b.step(ctx, "listener"); err != nil {
				return err
			}
			family := byte(unix.NFPROTO_IPV4)
			if v6 {
				family = unix.NFPROTO_IPV6
			}
			rules := iif()
			rules = append(rules,
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
				&expr.Immediate{Register: 1, Data: []byte{1, 0, 0, 0}}, &expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
				&expr.Immediate{Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
				&expr.TProxy{Family: family, TableFamily: byte(nftables.TableFamilyINet), RegPort: 1}, &expr.Verdict{Kind: expr.VerdictAccept})
			conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: rules})
		}
	}
	err = namespaceRun(ctx, b.ns, func() error {
		if err := conn.Flush(); err != nil {
			return err
		}
		return b.step(ctx, "netfilter")
	})
	return kernelError("private transparent ingress", NetfilterUnavailable, err)
}

func (b *kernelBackend) ingressSocket(ctx context.Context, local netip.Addr, protocol byte) (int, error) {
	var listener net.Listener
	var packet net.PacketConn
	err := namespaceRun(ctx, b.ns, func() error {
		var err error
		config := net.ListenConfig{Control: socketOptions(true, protocol == unix.IPPROTO_UDP)}
		address := net.JoinHostPort(local.String(), "0")
		if protocol == unix.IPPROTO_TCP {
			listener, err = config.Listen(ctx, family("tcp", local), address)
		} else {
			packet, err = config.ListenPacket(ctx, family("udp", local), address)
		}
		if err != nil {
			return err
		}
		return b.step(ctx, "ingress-socket")
	})
	if err != nil {
		if listener != nil {
			err = errors.Join(err, cleanupError("failed listener close", listener.Close()))
		}
		if packet != nil {
			err = errors.Join(err, cleanupError("failed packet listener close", packet.Close()))
		}
		return 0, kernelError("private listener", RuntimeFailure, err)
	}
	if listener != nil {
		owned := b.recordCloser(listener)
		if _, err = b.owner.Track(owned); err != nil {
			return 0, errors.Join(err, cleanupError("rejected listener close", owned.Close()))
		}
		b.workers.Go(func() { b.acceptTCP(listener) })
		return listener.Addr().(*net.TCPAddr).Port, nil
	}
	owned := b.recordCloser(packet)
	if _, err = b.owner.Track(owned); err != nil {
		return 0, errors.Join(err, cleanupError("rejected packet listener close", owned.Close()))
	}
	b.workers.Go(func() { b.acceptUDP(packet.(*net.UDPConn)) })
	return packet.LocalAddr().(*net.UDPAddr).Port, nil
}

func (b *kernelBackend) acceptTCP(listener net.Listener) {
	limit := b.ingressSlots
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case limit <- struct{}{}:
		default:
			_ = b.recordCloser(c).Close()
			continue
		}
		owned, err := b.ownConn(c)
		if err != nil {
			<-limit
			continue
		}
		b.workers.Go(func() {
			defer func() { _ = owned.Close(); <-limit }()
			source := unscopedEndpoint(c.RemoteAddr().(*net.TCPAddr).AddrPort())
			destination := unscopedEndpoint(c.LocalAddr().(*net.TCPAddr).AddrPort())
			authenticatedDispatcher{b.e}.TCP(b.e.ctx, owned, source, destination)
		})
	}
}

type ingressTuple struct{ source, destination netip.AddrPort }

func originalDestination(oob []byte) (netip.AddrPort, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, msg := range msgs {
		if (msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_ORIGDSTADDR) || (msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_ORIGDSTADDR) {
			sa, err := unix.ParseOrigDstAddr(&msg)
			if err != nil {
				return netip.AddrPort{}, err
			}
			switch sa := sa.(type) {
			case *unix.SockaddrInet4:
				return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port)), nil
			case *unix.SockaddrInet6:
				return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), uint16(sa.Port)), nil
			}
		}
	}
	return netip.AddrPort{}, errors.New("AmneziaWG original UDP destination absent")
}

func (b *kernelBackend) acceptUDP(listener *net.UDPConn) {
	var mu sync.Mutex
	flows := map[ingressTuple]*kernelUDPFlow{}
	data, oob := make([]byte, 65535), make([]byte, 256)
	for {
		n, control, flags, source, err := listener.ReadMsgUDPAddrPort(data, oob)
		if err != nil {
			return
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			continue
		}
		destination, err := originalDestination(oob[:control])
		if err != nil {
			continue
		}
		source, destination = unscopedEndpoint(source), unscopedEndpoint(destination)
		key := ingressTuple{source, destination}
		mu.Lock()
		flow := flows[key]
		mu.Unlock()
		if flow == nil {
			select {
			case b.ingressSlots <- struct{}{}:
			default:
				continue
			}
			socket, err := b.dialUDP(b.e.ctx, destination, source)
			if err != nil {
				if socket != nil {
					_ = b.recordCloser(socket).Close()
				}
				<-b.ingressSlots
				continue
			}
			flow = &kernelUDPFlow{Conn: socket, packets: make(chan []byte, 256), done: make(chan struct{}), changed: make(chan struct{})}
			flow.release = func() { mu.Lock(); delete(flows, key); mu.Unlock(); <-b.ingressSlots }
			ownedFlow := b.recordCloser(flow)
			release, err := b.owner.Track(ownedFlow)
			if err != nil {
				_ = ownedFlow.Close()
				return
			}
			mu.Lock()
			flows[key] = flow
			mu.Unlock()
			f := flow
			b.workers.Go(func() {
				defer release()
				defer ownedFlow.Close()
				authenticatedDispatcher{b.e}.UDP(b.e.ctx, f, source, destination)
			})
			b.workers.Go(func() {
				buffer := make([]byte, 65535)
				for {
					n, err := f.Conn.Read(buffer)
					if err != nil {
						_ = f.Close()
						return
					}
					f.enqueue(buffer[:n])
				}
			})
		}
		flow.enqueue(data[:n])
	}
}

// A datagram flow combines the first TPROXY packet with later packets received
// on its kernel connected socket. Queues are bounded; deadline changes wake
// existing readers, and Close joins through kernelBackend.workers.
type kernelUDPFlow struct {
	net.Conn
	packets  chan []byte
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
	release  func()
	closeErr error
}

func (f *kernelUDPFlow) enqueue(p []byte) {
	select {
	case <-f.done:
		return
	default:
	}
	select {
	case f.packets <- append(make([]byte, 0, len(p)), p...):
	default:
	}
}

func (f *kernelUDPFlow) Read(p []byte) (int, error) {
	for {
		f.mu.Lock()
		deadline, changed := f.deadline, f.changed
		f.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var packet []byte
		var err error
		select {
		case <-f.done:
			err = net.ErrClosed
		case <-timeout:
			err = os.ErrDeadlineExceeded
		case <-changed:
		case packet = <-f.packets:
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return 0, err
		}
		if packet != nil {
			return copy(p, packet), nil
		}
	}
}

func (f *kernelUDPFlow) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline = t
	close(f.changed)
	f.changed = make(chan struct{})
	return nil
}

func (f *kernelUDPFlow) SetDeadline(t time.Time) error {
	return errors.Join(f.SetReadDeadline(t), f.SetWriteDeadline(t))
}

func (f *kernelUDPFlow) Close() error {
	f.once.Do(func() {
		close(f.done)
		f.closeErr = f.Conn.Close()
		if f.release != nil {
			f.release()
		}
	})
	return f.closeErr
}
