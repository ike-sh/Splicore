package clientruntime

import (
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var errUDPPacket = errors.New("invalid SOCKS UDP datagram")

const maxAssociationFlows = 32

func parseUDPPacket(b []byte) (access.Endpoint, []byte, error) { return socks5.ParsePacket(b) }
func encodeUDPPacket(a net.Addr, p []byte) ([]byte, error) {
	target, e := netaddr.From(a)
	if e != nil {
		return nil, e
	}
	return socks5.EncodePacket(target, p)
}

type udpFlow struct {
	net.PacketConn
	dead atomic.Bool
}
type retiredUDPFlow struct {
	key   access.Endpoint
	owner *udpFlow
}

func (m *Manager) serveUDP(ctx context.Context, s *session, reader io.Reader, requested access.Endpoint, gen *snapshot) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reply := func(code byte, addr net.Addr) error {
		return socks.Respond(s.local, code, addr)
	}
	peer := s.local.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	requestedIP, parseErr := netip.ParseAddr(requested.Host)
	if parseErr != nil || !requestedIP.IsUnspecified() && requestedIP.Unmap() != peer {
		_ = reply(socks.NotAllowed, s.local.LocalAddr())
		return
	}
	localIP := s.local.LocalAddr().(*net.TCPAddr).IP
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP})
	if err != nil {
		_ = reply(socks.Failure, s.local.LocalAddr())
		return
	}
	m.mu.Lock()
	s.packet = relay
	closed := m.closed || ctx.Err() != nil
	m.mu.Unlock()
	if closed {
		_ = relay.Close()
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = relay.Close(); _ = s.local.Close() })
	defer stop()
	flows := map[access.Endpoint]*udpFlow{}
	type flowSelection struct {
		target   access.Endpoint
		counters []*counter
		health   *dialerLease
	}
	selections := map[access.Endpoint]flowSelection{}
	affinity := map[identity.ID]P.Action{}
	counters := []*counter{&s.stats, gen.inCounters[s.inbound], gen.accountCounters[s.account]}
	counted := map[*counter]bool{}
	for _, c := range counters {
		if c != nil {
			counted[c] = true
		}
	}
	finished := make(chan retiredUDPFlow, maxAssociationFlows)
	var workers sync.WaitGroup
	// Only this receive loop creates flows and adds workers. It finishes before
	// cleanup begins Wait, so no flow can be registered during shutdown.
	defer func() {
		cancel()
		_ = relay.Close()
		_ = s.local.Close()
		for _, pc := range flows {
			_ = pc.Close()
		}
		workers.Wait()
	}()
	for _, c := range counters {
		if c != nil {
			c.udpTotal.Add(1)
			c.udpActive.Add(1)
		}
	}
	defer func() {
		for _, c := range counters {
			if c != nil {
				c.udpActive.Add(-1)
			}
		}
	}()
	if reply(socks.Succeeded, relay.LocalAddr()) != nil {
		return
	}
	_ = s.local.SetDeadline(time.Time{})
	workers.Add(1)
	go func() { defer workers.Done(); _, _ = io.Copy(io.Discard, reader); cancel(); _ = relay.Close() }()
	b := make([]byte, 65535)
	pinnedPort := int(requested.Port)
	_ = relay.SetReadDeadline(time.Now().Add(m.udpIdle))
	for {
		n, source, err := relay.ReadFromUDP(b)
		if err != nil {
			return
		}
		if source.AddrPort().Addr().Unmap() != peer || pinnedPort != 0 && source.Port != pinnedPort {
			continue
		}
		target, payload, err := parseUDPPacket(b[:n])
		if err != nil {
			continue
		}
		if pinnedPort == 0 {
			pinnedPort = source.Port
		}
		_ = relay.SetReadDeadline(time.Now().Add(m.udpIdle))
		for draining := true; draining; {
			select {
			case retired := <-finished:
				if flows[retired.key] == retired.owner {
					delete(flows, retired.key)
					delete(selections, retired.key)
				}
			default:
				draining = false
			}
		}
		pc := flows[target]
		if pc != nil && pc.dead.Load() {
			delete(flows, target)
			delete(selections, target)
			pc = nil
		}
		if pc == nil {
			if len(flows) >= maxAssociationFlows {
				continue
			}
			dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			decision, resolved, routeErr := selectRoute(dialCtx, gen, s.inbound, target, "udp", affinity)
			if routeErr != nil || decision.Selected.Kind == P.Reject {
				cancel()
				continue
			}
			oid := selectedOutbound(decision.Selected)
			health := gen.outbounds[oid].(*dialerLease)
			pd, ok := health.dialer.(ports.ClientPacketDialer)
			if !ok {
				cancel()
				continue
			}
			var raw net.PacketConn
			raw, err = pd.ListenPacket(dialCtx, resolved)
			cancel()
			if err != nil {
				health.failed()
				continue
			}
			pc = &udpFlow{PacketConn: raw}
			if ctx.Err() != nil {
				_ = pc.Close()
				return
			}
			flows[target] = pc
			var node identity.ID
			for _, o := range gen.state.Outbounds {
				if o.ID == oid && o.NodeID != nil {
					node = *o.NodeID
				}
			}
			m.mu.Lock()
			if s.outbound == "" {
				s.outbound = oid
				s.node = node
				s.dialer = health
			}
			m.mu.Unlock()
			flowCounters := []*counter{&s.stats, gen.inCounters[s.inbound], gen.outCounters[oid], gen.nodeCounters[node], gen.accountCounters[s.account]}
			for _, c := range flowCounters {
				if c != nil && !counted[c] {
					counted[c] = true
					c.udpTotal.Add(1)
					c.udpActive.Add(1)
					counters = append(counters, c)
				}
			}
			selections[target] = flowSelection{resolved, flowCounters, health}
			destination := *source // immutable per-association destination, never scratch state
			workers.Add(1)
			go func(pc *udpFlow, key access.Endpoint, counters []*counter, health *dialerLease) {
				defer workers.Done()
				defer func() {
					pc.dead.Store(true)
					_ = pc.Close()
					select {
					case finished <- retiredUDPFlow{key, pc}:
					case <-ctx.Done():
					}
				}()
				response := make([]byte, 65535)
				for {
					_ = pc.SetReadDeadline(time.Now().Add(m.udpIdle))
					n, addr, err := pc.ReadFrom(response)
					if err != nil {
						if ctx.Err() == nil {
							health.failed()
						}
						return
					}
					frame, err := encodeUDPPacket(addr, response[:n])
					if err != nil {
						continue
					}
					sent, err := relay.WriteToUDP(frame, &destination)
					if err != nil {
						return
					}
					if sent != len(frame) {
						continue
					}
					_ = relay.SetReadDeadline(time.Now().Add(m.udpIdle))
					health.success()
					for _, c := range counters {
						if c != nil {
							c.download.Add(int64(n))
							c.packetsDown.Add(1)
						}
					}
				}
			}(pc, target, flowCounters, health)
		}
		flow := selections[target]
		_ = pc.SetReadDeadline(time.Now().Add(m.udpIdle))
		_ = pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
		written, err := pc.WriteTo(payload, netaddr.UDP(flow.target))
		if err != nil {
			flow.health.failed()
			pc.dead.Store(true)
			_ = pc.Close()
			if flows[target] == pc {
				delete(flows, target)
				delete(selections, target)
			}
			continue
		}
		// Some inherited packet wrappers return frame bytes; account only payload.
		written = min(written, len(payload))
		for _, c := range flow.counters {
			if c != nil {
				c.upload.Add(int64(written))
				c.packetsUp.Add(1)
			}
		}
	}
}

// DIRECT resolves only this target flow, retaining the canonical domain in SQLite.
func (d directDialer) ListenPacket(ctx context.Context, e access.Endpoint) (net.PacketConn, error) {
	c, err := d.protected.DialContext(ctx, "udp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))))
	if err != nil {
		return nil, err
	}
	return &directPacket{c.(*net.UDPConn)}, nil
}

type directPacket struct{ *net.UDPConn }

func (c *directPacket) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
