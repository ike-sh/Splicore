package networkruntime

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
)

// ExchangeDNS uses the Phase 12 matcher, detours, trust checks and bounded cache.
// It accepts one standard IN question, never raw caller-selected upstreams.
func (e *Engine) ExchangeDNS(ctx context.Context, wire []byte, tcp bool) ([]byte, error) {
	if !e.config.DNS.Enabled {
		return nil, identity.Err(identity.Invalid, "DNS interception is disabled")
	}
	request, domain, err := decodeInterceptedDNS(wire)
	if err != nil {
		return nil, err
	}
	return e.exchangeInterceptedDNS(ctx, request, domain, tcp)
}

func decodeInterceptedDNS(wire []byte) (*dns.Msg, string, error) {
	if len(wire) < 12 || len(wire) > 65535 {
		return nil, "", identity.Err(identity.Invalid, "invalid intercepted DNS request")
	}
	request := new(dns.Msg)
	if request.Unpack(wire) != nil || request.Response || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 || request.Question[0].Qclass != dns.ClassINET || len(request.Answer) > 0 || len(request.Ns) > 0 {
		return nil, "", identity.Err(identity.Invalid, "unsupported intercepted DNS request")
	}
	if len(request.Extra) > 1 {
		return nil, "", identity.Err(identity.Invalid, "unsupported DNS additional section")
	}
	for _, extra := range request.Extra {
		if opt, ok := extra.(*dns.OPT); !ok || opt.Version() != 0 {
			return nil, "", identity.Err(identity.Invalid, "unsupported DNS additional section")
		}
	}
	domain, err := P.Domain(strings.TrimSuffix(request.Question[0].Name, "."))
	return request, domain, err
}

func (e *Engine) exchangeInterceptedDNS(ctx context.Context, request *dns.Msg, domain string, tcp bool) ([]byte, error) {
	ctx, done, err := e.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(e.config.DNS.TimeoutSeconds)*time.Second)
	defer cancel()
	id := e.Matcher.DNSServer(domain, e.config.DNS.DefaultServer)
	var server P.DNSServer
	for _, s := range e.config.Servers {
		if s.ID == id {
			server = s
			break
		}
	}
	if server.ID == "" {
		return nil, identity.Err(identity.Invalid, "missing DNS server")
	}
	response := new(dns.Msg)
	response.SetReply(request)
	if server.Type == "system" {
		e.dnsQueries.Add(1)
		e.dnsMisses.Add(1)
		e.dnsCounts[id].queries.Add(1)
		network := "ip4"
		if request.Question[0].Qtype == dns.TypeAAAA {
			network = "ip6"
		} else if request.Question[0].Qtype != dns.TypeA {
			response.Rcode = dns.RcodeNotImplemented
		}
		if response.Rcode == dns.RcodeSuccess {
			var ips []netip.Addr
			ips, err = e.systemLookup(ctx, network, domain)
			for _, ip := range ips {
				header := dns.RR_Header{Name: request.Question[0].Name, Rrtype: request.Question[0].Qtype, Class: dns.ClassINET, Ttl: 30}
				if ip.Is4() {
					response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.IP(ip.AsSlice())})
				} else {
					response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.IP(ip.AsSlice())})
				}
			}
		}
	} else {
		action, selectErr := e.Select(server.Detour, nil, true, 0)
		if selectErr != nil {
			return nil, selectErr
		}
		endpoint := server.Endpoint
		if _, parseErr := netip.ParseAddr(endpoint.Host); parseErr != nil {
			ips, resolveErr := e.Bootstrap(ctx, endpoint.Host)
			if resolveErr != nil || len(ips) == 0 {
				return nil, identity.Err(identity.Unavailable, "DNS bootstrap failed")
			}
			endpoint.Host = ips[0].String()
		}
		response, _, err = e.question(ctx, server, endpoint, action, domain, "interception", request.Question[0].Qtype)
	}
	if err != nil {
		e.dnsFailures.Add(1)
		e.dnsCounts[id].failures.Add(1)
		return nil, identity.Err(identity.Unavailable, "intercepted DNS exchange failed")
	}
	response.Id = request.Id
	response.Question = append([]dns.Question(nil), request.Question...)
	response.Response = true
	response.RecursionDesired = request.RecursionDesired
	response.RecursionAvailable = true
	// Existing upstream DNS exchanges do not expose DNSSEC validation semantics.
	response.AuthenticatedData = false
	e.observeDNS(domain, response)
	if !tcp {
		size := uint16(512)
		if opt := request.IsEdns0(); opt != nil {
			size = max(512, min(opt.UDPSize(), 4096))
		}
		response.Truncate(int(size))
	}
	wire, err := response.Pack()
	if len(wire) > 65535 {
		return nil, identity.Err(identity.Unavailable, "DNS reply exceeds framing limit")
	}
	return wire, err
}

type dnsBinding struct {
	domain  string
	expires time.Time
}

// Observed addresses are real DNS answers, never FakeIP. A shared address with
// competing names loses its domain annotation rather than guessing a policy.
func (e *Engine) observeDNS(domain string, response *dns.Msg) {
	if response.Rcode != dns.RcodeSuccess || response.Truncated {
		return
	}
	// Only bind addresses belonging to the question or its bounded CNAME chain.
	owners := map[string]bool{dns.CanonicalName(domain): true}
	for range 16 {
		changed := false
		for _, rr := range response.Answer {
			if cname, ok := rr.(*dns.CNAME); ok && owners[dns.CanonicalName(cname.Hdr.Name)] {
				name := dns.CanonicalName(cname.Target)
				if !owners[name] {
					owners[name] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	e.dnsMu.Lock()
	defer e.dnsMu.Unlock()
	if e.bindings == nil {
		e.bindings = map[netip.Addr]dnsBinding{}
	}
	now := time.Now()
	for _, rr := range response.Answer {
		if !owners[dns.CanonicalName(rr.Header().Name)] || rr.Header().Class != dns.ClassINET {
			continue
		}
		var raw net.IP
		switch a := rr.(type) {
		case *dns.A:
			raw = a.A
		case *dns.AAAA:
			raw = a.AAAA
		default:
			continue
		}
		ip, ok := netip.AddrFromSlice(raw)
		if !ok || rr.Header().Ttl == 0 {
			continue
		}
		ip = ip.Unmap()
		expires := now.Add(time.Duration(min(rr.Header().Ttl, 300)) * time.Second)
		prior, exists := e.bindings[ip]
		if exists && now.Before(prior.expires) && prior.domain != domain {
			if prior.expires.After(expires) {
				expires = prior.expires
			}
			e.bindings[ip] = dnsBinding{"", expires}
			continue
		}
		if !exists && len(e.bindings) >= 4096 {
			for addr, b := range e.bindings {
				if !now.Before(b.expires) {
					delete(e.bindings, addr)
				}
			}
			if len(e.bindings) >= 4096 {
				continue
			}
		}
		e.bindings[ip] = dnsBinding{domain, expires}
	}
}
func (e *Engine) ObservedDomain(ip netip.Addr) string {
	e.dnsMu.Lock()
	defer e.dnsMu.Unlock()
	binding := e.bindings[ip.Unmap()]
	if !time.Now().Before(binding.expires) {
		delete(e.bindings, ip.Unmap())
		return ""
	}
	return binding.domain
}
