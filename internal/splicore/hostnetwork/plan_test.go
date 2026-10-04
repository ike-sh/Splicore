package hostnetwork

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/domain/client"
)

func TestBootstrapMappedIPv4UsesIPv4BypassRoute(t *testing.T) {
	p := NewPlatform()
	plan, err := p.Plan(context.Background(), client.TUNSettings{
		Interface: "plan13only", Addresses: []string{"198.18.249.1/30", "fd13:249::1/126"}, MTU: 1500,
	}, []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.17"), netip.MustParseAddr("192.0.2.17")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan.Bypass, "192.0.2.17/32") {
		t.Fatal("bootstrap IPv4 bypass missing", plan.Bypass)
	}
	count := 0
	for _, raw := range plan.Bypass {
		prefix := netip.MustParsePrefix(raw)
		if prefix.Addr().Is4In6() {
			t.Fatal("mapped address became an IPv6 route", raw)
		}
		if raw == "192.0.2.17/32" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("duplicate bootstrap representations produced duplicate routes", count)
	}
}
