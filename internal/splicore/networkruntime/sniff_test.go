package networkruntime

import (
	"net/netip"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
)

func TestSniffedDomainOrderedRoutes(t *testing.T) {
	guard := identity.ID("00000000-0000-4000-8000-000000000001")
	allow := P.RouteRule{ID: "00000000-0000-4000-8000-000000000002", Name: "allow", Match: P.RuleMatch{LocalInbounds: []identity.ID{guard}, SniffedDomains: []string{"www.3verge.com", "approved-b.test"}}, Action: P.Action{Kind: P.Direct}}
	deny := P.RouteRule{ID: "00000000-0000-4000-8000-000000000003", Name: "block", Match: P.RuleMatch{LocalInbounds: []identity.ID{guard}}, Action: P.Action{Kind: P.Reject}}
	m, e := Compile(P.Config{Route: P.RouteProfile{Rules: []P.RouteRule{allow, deny}}})
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"www.3verge.com", "WWW.3VERGE.COM.", "approved-b.test", "example.com", "evilwww.3verge.com", "www.3verge.com.attacker.example", "3verge.com", "", "127.0.0.1", "a..test"} {
		q := Query{IP: netip.MustParseAddr("127.0.0.1"), Domain: "www.3verge.com", Port: 443, Network: "tcp", LocalInbound: guard, SniffedProtocol: "tls", SniffedDomain: name}
		want := P.Reject
		if name == "www.3verge.com" || name == "WWW.3VERGE.COM." || name == "approved-b.test" {
			want = P.Direct
		}
		if got := m.Match(q, P.Action{Kind: P.Direct}, false); got.Action.Kind != want {
			t.Fatal(name, got)
		}
	}
	q := Query{Domain: "www.3verge.com", Port: 443, Network: "tcp", LocalInbound: guard}
	if got := m.Match(q, P.Action{Kind: P.Direct}, false); got.Action.Kind != P.Reject {
		t.Fatal("configured destination impersonated SNI", got)
	}
	q.LocalInbound = "00000000-0000-4000-8000-000000000004"
	if got := m.Match(q, P.Action{Kind: P.Direct}, false); got.Action.Kind != P.Direct {
		t.Fatal("guard fallback escaped scope", got)
	}
	reversed, e := Compile(P.Config{Route: P.RouteProfile{Rules: []P.RouteRule{deny, allow}}})
	if e != nil {
		t.Fatal(e)
	}
	q.LocalInbound = guard
	q.SniffedProtocol = "tls"
	q.SniffedDomain = "www.3verge.com"
	if got := reversed.Match(q, P.Action{Kind: P.Direct}, false); got.Action.Kind != P.Reject {
		t.Fatal("first match order ignored", got)
	}
}
