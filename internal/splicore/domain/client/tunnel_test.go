package client

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
)

func guardProfile() ProfileState {
	s := Empty()
	id := identity.ID("00000000-0000-4000-8000-000000000001")
	s.LocalInbounds = []LocalInbound{{ID: id, Name: "guard", Kind: "tunnel", Listen: access.Endpoint{Host: "127.0.0.1", Port: 39000}, Tunnel: &TunnelSettings{Target: access.Endpoint{Host: "www.3verge.com", Port: 443}, Network: "tcp"}, Sniffing: &SniffingPolicy{Enabled: true, Protocols: []string{"tls"}, RouteOnly: true}}}
	s.Network.Route.Rules = []P.RouteRule{{ID: "00000000-0000-4000-8000-000000000002", Name: "allow", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}, SniffedDomains: []string{"WWW.3VERGE.COM."}}, Action: P.Action{Kind: P.Direct}}, {ID: "00000000-0000-4000-8000-000000000003", Name: "deny", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}}, Action: P.Action{Kind: P.Reject}}}
	return s
}

func TestTunnelIntentValidation(t *testing.T) {
	if e := guardProfile().Validate(); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name   string
		change func(*ProfileState)
	}{
		{"missing target", func(s *ProfileState) { s.LocalInbounds[0].Tunnel = nil }},
		{"empty address", func(s *ProfileState) { s.LocalInbounds[0].Tunnel.Target.Host = "" }},
		{"target port zero", func(s *ProfileState) { s.LocalInbounds[0].Tunnel.Target.Port = 0 }},
		{"listen port zero", func(s *ProfileState) { s.LocalInbounds[0].Listen.Port = 0 }},
		{"UDP", func(s *ProfileState) { s.LocalInbounds[0].Tunnel.Network = "udp" }},
		{"TCP UDP", func(s *ProfileState) { s.LocalInbounds[0].Tunnel.Network = "tcp,udp" }},
		{"sniff missing", func(s *ProfileState) { s.LocalInbounds[0].Sniffing = nil }},
		{"sniff disabled", func(s *ProfileState) { s.LocalInbounds[0].Sniffing.Enabled = false }},
		{"sniff no override", func(s *ProfileState) { s.LocalInbounds[0].Sniffing.Protocols = nil }},
		{"sniff unsupported", func(s *ProfileState) { s.LocalInbounds[0].Sniffing.Protocols = []string{"http"} }},
		{"target rewrite", func(s *ProfileState) { s.LocalInbounds[0].Sniffing.RouteOnly = false }},
		{"public IPv4", func(s *ProfileState) { s.LocalInbounds[0].Listen.Host = "0.0.0.0" }},
		{"public IPv6", func(s *ProfileState) { s.LocalInbounds[0].Listen.Host = "::" }},
		{"DNS listener", func(s *ProfileState) { s.LocalInbounds[0].Listen.Host = "localhost" }},
		{"allow LAN", func(s *ProfileState) { s.LocalInbounds[0].AllowLAN = true }},
		{"self target", func(s *ProfileState) { s.LocalInbounds[0].Tunnel.Target = s.LocalInbounds[0].Listen }},
		{"mapped self", func(s *ProfileState) {
			s.LocalInbounds[0].Tunnel.Target = access.Endpoint{Host: "::ffff:127.0.0.1", Port: 39000}
		}},
		{"localhost self", func(s *ProfileState) {
			s.LocalInbounds[0].Tunnel.Target = access.Endpoint{Host: "LOCALHOST", Port: 39000}
		}},
		{"proxy auth", func(s *ProfileState) { s.LocalInbounds[0].Auth = true }},
		{"selected outbound", func(s *ProfileState) { s.LocalInbounds[0].SelectedOutbound = Direct }},
		{"wrong kind", func(s *ProfileState) { s.LocalInbounds[0].Kind = "socks5" }},
		{"duplicate identity", func(s *ProfileState) {
			i := s.LocalInbounds[0]
			i.Listen.Port++
			s.LocalInbounds = append(s.LocalInbounds, i)
		}},
		{"invalid exact domain", func(s *ProfileState) { s.Network.Route.Rules[0].Match.SniffedDomains = []string{"*.3verge.com"} }},
		{"IP domain", func(s *ProfileState) { s.Network.Route.Rules[0].Match.SniffedDomains = []string{"127.0.0.1"} }},
		{"configured domain used for allow", func(s *ProfileState) {
			s.Network.Route.Rules[0].Match.Domains = s.Network.Route.Rules[0].Match.SniffedDomains
			s.Network.Route.Rules[0].Match.SniffedDomains = nil
		}},
		{"missing fallback", func(s *ProfileState) { s.Network.Route.Rules = s.Network.Route.Rules[:1] }},
		{"broad allow", func(s *ProfileState) { s.Network.Route.Rules[0].Match.LocalInbounds = nil }},
		{"broad earlier route", func(s *ProfileState) {
			s.Network.Route.Rules = append([]P.RouteRule{{ID: "00000000-0000-4000-8000-000000000009", Name: "bypass", Action: P.Action{Kind: P.Direct}}}, s.Network.Route.Rules...)
		}},
		{"conditional fallback", func(s *ProfileState) { s.Network.Route.Rules[1].Match.Networks = []string{"tcp"} }},
		{"proxy fallback", func(s *ProfileState) { s.Network.Route.Rules[1].Action = P.Action{Kind: P.Direct} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := guardProfile()
			tc.change(&s)
			if e := s.Validate(); e == nil {
				t.Fatal("invalid guard accepted")
			}
		})
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		s := guardProfile()
		s.LocalInbounds[0].Listen.Host = host
		if e := s.Validate(); e != nil {
			t.Fatal(host, e)
		}
	}
	s := guardProfile()
	s.Network.Route.Rules = nil
	if e := s.Validate(); e != nil {
		t.Fatal("dormant guard must be configurable", e)
	}
	b, _ := json.Marshal(guardProfile().LocalInbounds[0])
	for _, port := range []string{"65536", "-1"} {
		raw := strings.Replace(string(b), `"port":443`, `"port":`+port, 1)
		var i LocalInbound
		if json.Unmarshal([]byte(raw), &i) == nil {
			t.Fatal("out of range port", port)
		}
	}
}
