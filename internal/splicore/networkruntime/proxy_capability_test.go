package networkruntime

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"net"
	"net/netip"
	"testing"
)

type proxyCapabilityFixture bool

func (d proxyCapabilityFixture) SupportsNetwork(n string) bool {
	return n == "tcp" || n == "udp" && bool(d)
}
func (proxyCapabilityFixture) DialContext(context.Context, access.Endpoint) (net.Conn, error) {
	panic("dry selection performed network I/O")
}
func (proxyCapabilityFixture) Close() error { return nil }
func TestPhase20PolicyFiltersHTTPUDP(t *testing.T) {
	members := []P.Action{{Kind: P.Outbound, ID: testID(1)}, {Kind: P.Outbound, ID: testID(2)}}
	for _, kind := range []string{"selector", "fallback", "url_test", "load_balance"} {
		g := P.PolicyGroup{ID: testID(3), Name: "proxy policy", Type: kind, Members: members}
		switch kind {
		case "selector":
			g.Selector = &P.SelectorSettings{Selected: members[0]}
		case "fallback":
			g.Fallback = &P.FallbackSettings{Probe: P.Probe{URL: "http://probe.invalid/", IntervalSeconds: 60, TimeoutSeconds: 1, ExpectedStatus: 200}}
		case "url_test":
			g.URLTest = &P.URLTestSettings{Probe: P.Probe{URL: "http://probe.invalid/", IntervalSeconds: 60, TimeoutSeconds: 1, ExpectedStatus: 200}}
		case "load_balance":
			g.LoadBalance = &P.LoadBalanceSettings{Algorithm: "round_robin"}
		}
		e, err := New(P.Config{Groups: []P.PolicyGroup{g}}, map[identity.ID]ports.ClientDialer{testID(1): proxyCapabilityFixture(false), testID(2): proxyCapabilityFixture(true)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range members {
			e.groups[g.ID].samples[m] = Sample{State: "healthy", LatencyMS: 1}
		}
		decision, err := e.Explain(Query{IP: netip.MustParseAddr("127.0.0.1"), Port: 53, Network: "udp"}, P.Action{Kind: P.Group, ID: g.ID}, true, nil)
		if kind == "selector" {
			if err == nil || decision.Available {
				t.Fatal("HTTP selector UDP accepted")
			}
		} else if err != nil || decision.Selected != members[1] {
			t.Fatal("UDP group did not skip HTTP", kind, err)
		}
		e.Close()
	}
}
