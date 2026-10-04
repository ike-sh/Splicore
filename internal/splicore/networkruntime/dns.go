package networkruntime

import (
	"container/list"
	"context"
	"encoding/json"
	"github.com/miekg/dns"
	T "github.com/sagernet/sing-box/common/tls"
	D "github.com/sagernet/sing-box/dns"
	transport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func effectiveGroup(g P.PolicyGroup) string { g.Name = ""; b, _ := json.Marshal(g); return string(b) }

type connectedPacket struct {
	net.PacketConn
	remote net.Addr
}

func (c *connectedPacket) Read(b []byte) (int, error)  { n, _, err := c.ReadFrom(b); return n, err }
func (c *connectedPacket) Write(b []byte) (int, error) { return c.WriteTo(b, c.remote) }
func (c *connectedPacket) RemoteAddr() net.Addr        { return c.remote }
func (e *Engine) dial(ctx context.Context, a P.Action, network string, target access.Endpoint) (net.Conn, error) {
	return e.dialPurpose(ctx, a, network, target, underlay.DNSUpstream)
}
func (e *Engine) dialPurpose(ctx context.Context, a P.Action, network string, target access.Endpoint, purpose underlay.Purpose) (net.Conn, error) {
	purpose = underlay.PurposeFrom(ctx, purpose)
	ctx, done, err := e.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if a.Kind == P.Reject || a.Kind == P.Group {
		return nil, unavailable()
	}
	var conn net.Conn
	if a.Kind == P.Direct {
		d, buildErr := e.underlay.New(underlay.Scope{Purpose: purpose, Generation: e.generation})
		if buildErr != nil {
			return nil, buildErr
		}
		conn, err = d.DialContext(ctx, network, net.JoinHostPort(target.Host, portString(target.Port)))
	} else {
		d := e.dialers[a.ID]
		if d == nil {
			return nil, unavailable()
		}
		if network == "tcp" {
			conn, err = d.DialContext(ctx, target)
		} else {
			p, ok := d.(ports.ClientPacketDialer)
			if !ok {
				return nil, unavailable()
			}
			var pc net.PacketConn
			pc, err = p.ListenPacket(ctx, target)
			if err == nil {
				conn = &connectedPacket{pc, M.ParseSocksaddrHostPort(target.Host, target.Port)}
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return e.owner.Conn(conn)
}

type dnsDialer struct {
	engine *Engine
	action P.Action
}

func (d dnsDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	return d.engine.dial(ctx, d.action, network, access.Endpoint{Host: dst.AddrString(), Port: dst.Port})
}
func (d dnsDialer) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	return nil, identity.Err(identity.NotImplemented, "DNS transport uses connected TCP/UDP only")
}
func portString(p uint16) string { return strconv.Itoa(int(p)) }

type dnsKey struct {
	server           identity.ID
	member           P.Action
	strategy, domain string
	kind             uint16
}
type cacheEntry struct {
	key     dnsKey
	message *dns.Msg
	expires time.Time
	stored  time.Time
}
type dnsCache struct {
	capacity   int
	entries    map[dnsKey]*list.Element
	order      *list.List
	generation uint64
}

func newDNSCache(capacity int) *dnsCache {
	return &dnsCache{capacity: capacity, entries: map[dnsKey]*list.Element{}, order: list.New()}
}
func (c *dnsCache) get(k dnsKey, now time.Time) (*dns.Msg, bool) {
	elem := c.entries[k]
	if elem == nil {
		return nil, false
	}
	entry := elem.Value.(cacheEntry)
	if !now.Before(entry.expires) {
		delete(c.entries, k)
		c.order.Remove(elem)
		return nil, false
	}
	c.order.MoveToFront(elem)
	message := entry.message.Copy()
	elapsed := uint32(max(0, now.Sub(entry.stored)/time.Second))
	for _, section := range [][]dns.RR{message.Answer, message.Ns, message.Extra} {
		for _, rr := range section {
			if _, opt := rr.(*dns.OPT); !opt {
				rr.Header().Ttl -= min(rr.Header().Ttl, elapsed)
			}
		}
	}
	return message, true
}
func (c *dnsCache) put(k dnsKey, m *dns.Msg, ttl uint32) {
	if c.capacity == 0 || ttl == 0 {
		return
	}
	if elem := c.entries[k]; elem != nil {
		c.order.Remove(elem)
		delete(c.entries, k)
	}
	now := time.Now()
	elem := c.order.PushFront(cacheEntry{key: k, message: m.Copy(), expires: now.Add(time.Duration(ttl) * time.Second), stored: now})
	c.entries[k] = elem
	for c.order.Len() > c.capacity {
		old := c.order.Back()
		delete(c.entries, old.Value.(cacheEntry).key)
		c.order.Remove(old)
	}
}

type dnsCounters struct{ queries, failures atomic.Int64 }
type DNSResult struct {
	Server    identity.ID  `json:"server"`
	Strategy  string       `json:"strategy"`
	Addresses []netip.Addr `json:"addresses"`
	CacheHit  bool         `json:"cache_hit"`
}
type DNSServerStats struct {
	ID       identity.ID `json:"id"`
	Queries  int64       `json:"queries,string"`
	Failures int64       `json:"failures,string"`
}
type DNSStats struct {
	Queries  int64            `json:"queries,string"`
	Hits     int64            `json:"cache_hits,string"`
	Misses   int64            `json:"cache_misses,string"`
	Failures int64            `json:"failures,string"`
	Entries  int              `json:"entries"`
	Capacity int              `json:"capacity"`
	Servers  []DNSServerStats `json:"servers"`
}

func (e *Engine) DNSStats() DNSStats {
	s := DNSStats{Queries: e.dnsQueries.Load(), Hits: e.dnsHits.Load(), Misses: e.dnsMisses.Load(), Failures: e.dnsFailures.Load(), Servers: []DNSServerStats{}}
	e.dnsMu.Lock()
	s.Entries = len(e.cache.entries)
	s.Capacity = e.cache.capacity
	e.dnsMu.Unlock()
	for _, server := range e.config.Servers {
		c := e.dnsCounts[server.ID]
		s.Servers = append(s.Servers, DNSServerStats{server.ID, c.queries.Load(), c.failures.Load()})
	}
	return s
}
func (e *Engine) FlushCache() {
	e.dnsMu.Lock()
	generation := e.cache.generation + 1
	e.cache = newDNSCache(e.config.DNS.Cache.Capacity)
	e.cache.generation = generation
	e.dnsMu.Unlock()
}
func (e *Engine) Bootstrap(ctx context.Context, domain string) ([]netip.Addr, error) {
	ctx = underlay.WithPurpose(ctx, underlay.DNSBootstrap)
	if !e.config.DNS.Enabled {
		return e.systemLookup(ctx, "ip", domain)
	}
	result, err := e.lookup(ctx, domain, e.config.DNS.BootstrapServer, true)
	return result.Addresses, err
}
func (e *Engine) Lookup(ctx context.Context, domain string) (DNSResult, error) {
	if !e.config.DNS.Enabled {
		return DNSResult{}, identity.Err(identity.NotImplemented, "managed DNS is disabled")
	}
	return e.lookup(ctx, domain, e.Matcher.DNSServer(domain, e.config.DNS.DefaultServer), false)
}
func (e *Engine) lookup(ctx context.Context, domain string, id identity.ID, bootstrap bool) (out DNSResult, err error) {
	domain, err = P.Domain(domain)
	if err != nil {
		return out, err
	}
	ctx, done, err := e.owner.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(e.config.DNS.TimeoutSeconds)*time.Second)
	defer cancel()
	var server P.DNSServer
	for _, s := range e.config.Servers {
		if s.ID == id {
			server = s
			break
		}
	}
	if server.ID == "" {
		return out, identity.Err(identity.Invalid, "missing DNS server")
	}
	strategy := server.Strategy
	if strategy == "" {
		strategy = e.config.DNS.Strategy
	}
	if strategy == "" {
		strategy = "dual"
	}
	out = DNSResult{Server: id, Strategy: strategy, Addresses: []netip.Addr{}, CacheHit: true}
	if server.Type == "system" {
		e.dnsQueries.Add(1)
		e.dnsMisses.Add(1)
		e.dnsCounts[id].queries.Add(1)
		network := "ip"
		if strategy == "ipv4_only" {
			network = "ip4"
		}
		if strategy == "ipv6_only" {
			network = "ip6"
		}
		out.Addresses, err = e.systemLookup(ctx, network, domain)
		out.CacheHit = false
	} else {
		action := server.Detour
		if !bootstrap {
			action, err = e.Select(action, nil, true, 0)
			if err != nil {
				e.dnsFailures.Add(1)
				return out, err
			}
		}
		endpoint := server.Endpoint
		if _, parseErr := netip.ParseAddr(endpoint.Host); parseErr != nil {
			var ips []netip.Addr
			ips, err = e.Bootstrap(ctx, endpoint.Host)
			if err != nil || len(ips) == 0 {
				return out, identity.Err(identity.Unavailable, "DNS server bootstrap failed")
			}
			endpoint.Host = ips[0].String()
		}
		kinds := []uint16{dns.TypeA, dns.TypeAAAA}
		if strategy == "ipv4_only" {
			kinds = kinds[:1]
		}
		if strategy == "ipv6_only" {
			kinds = kinds[1:]
		}
		for _, kind := range kinds {
			var message *dns.Msg
			var hit bool
			message, hit, err = e.question(ctx, server, endpoint, action, domain, strategy, kind)
			out.CacheHit = out.CacheHit && hit
			if err != nil {
				break
			}
			if message.Rcode != dns.RcodeSuccess && message.Rcode != dns.RcodeNameError {
				err = identity.Err(identity.Unavailable, "DNS response failed")
				break
			}
			for _, rr := range message.Answer {
				switch answer := rr.(type) {
				case *dns.A:
					if kind == dns.TypeA {
						if ip, ok := netip.AddrFromSlice(answer.A); ok {
							out.Addresses = append(out.Addresses, ip.Unmap())
						}
					}
				case *dns.AAAA:
					if kind == dns.TypeAAAA {
						if ip, ok := netip.AddrFromSlice(answer.AAAA); ok {
							out.Addresses = append(out.Addresses, ip)
						}
					}
				}
				if len(out.Addresses) >= 32 {
					break
				}
			}
		}
	}
	if err == nil && len(out.Addresses) == 0 {
		err = identity.Err(identity.Unavailable, "DNS has no usable address")
	}
	if err != nil {
		e.dnsFailures.Add(1)
		e.dnsCounts[id].failures.Add(1)
		return out, identity.Err(identity.Unavailable, "DNS lookup failed")
	}
	if len(out.Addresses) > 32 {
		out.Addresses = out.Addresses[:32]
	}
	if strategy == "prefer_ipv6" || strategy == "prefer_ipv4" {
		preferred := []netip.Addr{}
		other := []netip.Addr{}
		for _, ip := range out.Addresses {
			if ip.Is6() == (strategy == "prefer_ipv6") {
				preferred = append(preferred, ip)
			} else {
				other = append(other, ip)
			}
		}
		out.Addresses = append(preferred, other...)
	}
	return out, nil
}
func (e *Engine) question(ctx context.Context, s P.DNSServer, endpoint access.Endpoint, action P.Action, domain, strategy string, kind uint16) (*dns.Msg, bool, error) {
	e.dnsQueries.Add(1)
	key := dnsKey{s.ID, action, strategy, domain, kind}
	e.dnsMu.Lock()
	cached, hit := e.cache.get(key, time.Now())
	generation := e.cache.generation
	e.dnsMu.Unlock()
	if hit {
		e.dnsHits.Add(1)
		return cached, true, nil
	}
	e.dnsMisses.Add(1)
	e.dnsCounts[s.ID].queries.Add(1)
	logger := log.NewNOPFactory().Logger()
	dialer := dnsDialer{e, action}
	addr := M.ParseSocksaddrHostPort(endpoint.Host, endpoint.Port)
	a := D.NewTransportAdapter(s.Type, string(s.ID), nil)
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(domain), kind)
	var conn net.Conn
	var response *dns.Msg
	var err error
	switch s.Type {
	case "udp":
		t := transport.NewUDPRaw(logger, a, dialer, addr)
		defer t.Close()
		response, err = t.Exchange(ctx, request)
	case "tcp":
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	case "dot":
		options := option.OutboundTLSOptions{Enabled: true, ServerName: s.TLS.ServerName}
		if s.TLS.CACertificate != "" {
			options.Certificate = badoption.Listable[string]{s.TLS.CACertificate}
		}
		tlsConfig, configErr := T.NewSTDClient(ctx, logger, s.Endpoint.Host, options)
		if configErr != nil {
			return nil, false, identity.Err(identity.Invalid, "invalid DNS trust store")
		}
		conn, err = T.NewDialer(dialer, tlsConfig).DialTLSContext(ctx, addr)
	default:
		return nil, false, identity.Err(identity.Invalid, "unsupported DNS transport")
	}
	if conn != nil {
		// One owned exchange, using the existing bounded DNS framing. No connection-reuse
		// probes that would introduce extra A/AAAA questions outside the chosen strategy.
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if err = transport.WriteMessage(conn, request.Id, request); err == nil {
			response, err = transport.ReadMessage(conn)
		}
	}
	if err != nil {
		return nil, false, identity.Err(identity.Unavailable, "DNS exchange failed")
	}
	if len(response.Question) != 1 || !strings.EqualFold(response.Question[0].Name, request.Question[0].Name) || response.Question[0].Qtype != kind {
		return nil, false, identity.Err(identity.Unavailable, "invalid DNS response")
	}
	ttl := dnsTTL(response)
	e.dnsMu.Lock()
	if generation == e.cache.generation {
		e.cache.put(key, response, ttl)
	}
	e.dnsMu.Unlock()
	return response, false, nil
}
func dnsTTL(m *dns.Msg) uint32 {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return 0
	}
	minimum := uint32(^uint32(0))
	for _, rr := range m.Answer {
		minimum = min(minimum, rr.Header().Ttl)
	}
	if len(m.Answer) == 0 || m.Rcode == dns.RcodeNameError {
		minimum = 0
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				minimum = min(soa.Hdr.Ttl, soa.Minttl)
				break
			}
		}
	}
	if minimum == ^uint32(0) {
		return 0
	}
	return minimum
}
