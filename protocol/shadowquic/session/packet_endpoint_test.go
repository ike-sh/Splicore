//go:build with_quic

package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
)

func TestUDPFixedTargetEndpointEquality(t *testing.T) {
	for _, tc := range []struct {
		name, left, right   string
		leftPort, rightPort uint16
		equal               bool
	}{
		{"compressed-expanded", "2001:db8::1", "2001:db8:0:0:0:0:0:1", 443, 443, true},
		{"expanded-compressed", "2001:db8:0:0:0:0:0:1", "2001:db8::1", 443, 443, true},
		{"canonical-ipv6", "2001:db8::1", "2001:db8::1", 443, 443, true},
		{"uppercase-ipv6", "2001:DB8::ABCD", "2001:db8::abcd", 443, 443, true},
		{"different-ipv6", "2001:db8::1", "2001:db8::2", 443, 443, false},
		{"ipv4-mapped", "192.0.2.10", "::ffff:192.0.2.10", 443, 443, true},
		{"mapped-ipv4", "::ffff:192.0.2.10", "192.0.2.10", 443, 443, true},
		{"mapped-hex-ipv4", "::FFFF:C000:020A", "192.0.2.10", 443, 443, true},
		{"different-mapped", "::ffff:192.0.2.10", "::ffff:192.0.2.11", 443, 443, false},
		{"different-ipv4", "192.0.2.10", "192.0.2.11", 443, 443, false},
		{"ipv4-port", "192.0.2.10", "192.0.2.10", 443, 8443, false},
		{"mapped-port", "::ffff:192.0.2.10", "192.0.2.10", 443, 8443, false},
		{"ipv6-port", "2001:db8::1", "2001:db8:0:0:0:0:0:1", 443, 8443, false},
		{"hostname", "target.test", "target.test", 53, 53, true},
		{"hostname-port", "target.test", "target.test", 53, 54, false},
		{"different-hostname", "target.test", "other.test", 53, 53, false},
		{"hostname-case-preserved", "Target.test", "target.test", 53, 53, false},
		{"hostname-ip", "localhost", "127.0.0.1", 53, 53, false},
		{"ip-hostname", "127.0.0.1", "localhost", 53, 53, false},
		{"malformed-left", "[2001:db8::1", "2001:db8::1", 443, 443, false},
		{"malformed-right", "2001:db8::1", "2001:db8::g", 443, 443, false},
		{"malformed-identical", "2001:db8::g", "2001:db8::g", 443, 443, false},
		{"invalid-numeric", "192.0.2.999", "192.0.2.999", 443, 443, false},
		{"empty-host", "", "", 443, 443, false},
		{"zero-port", "192.0.2.10", "192.0.2.10", 0, 0, false},
		{"scoped-ipv6", "fe80::1%eth0", "fe80::1%eth0", 443, 443, false},
		{"different-zone", "fe80::1%eth0", "fe80::1%eth1", 443, 443, false},
		{"zone-not-discarded", "fe80::1%eth0", "fe80::1", 443, 443, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := access.Endpoint{Host: tc.left, Port: tc.leftPort}
			b := access.Endpoint{Host: tc.right, Port: tc.rightPort}
			if got := sameUDPEndpoint(a, b); got != tc.equal {
				t.Fatalf("endpoint equality %v, %v = %v; want %v", a, b, got, tc.equal)
			}
		})
	}
}

func TestUDPFixedTargetMappingAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, pin, mapped string
		port              uint16
		allowed           bool
	}{
		{"expanded-ipv6-reply", "2001:db8:0:0:0:0:0:1", "2001:db8::1", 53, true},
		{"mapped-ipv4-reply", "::ffff:192.0.2.10", "192.0.2.10", 53, true},
		{"different-ip-reply", "2001:db8::1", "2001:db8::2", 53, false},
		{"different-port-reply", "2001:db8::1", "2001:db8::1", 54, false},
		{"hostname-reply", "target.test", "target.test", 53, true},
		{"hostname-ip-substitution", "localhost", "127.0.0.1", 53, false},
		{"malformed-reply", "2001:db8::1", "2001:db8::g", 53, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pin := access.Endpoint{Host: tc.pin, Port: 53}
			p := &packet{pinned: &pin}
			c := &connection{limits: Limits{MaxFlows: 1}, packets: map[*packet]bool{p: true}, receive: map[uint16]destination{}}
			err := c.register(p, access.Endpoint{Host: tc.mapped, Port: tc.port}, 1)
			if tc.allowed {
				if err != nil || len(c.receive) != 1 {
					t.Fatal("equivalent mapping rejected", err)
				}
			} else if !errors.Is(err, ErrLimit) || len(c.receive) != 0 {
				t.Fatal("invalid mapping admitted", err)
			}
		})
	}
}

func TestSessionUDPFixedTargetRepresentationReuse(t *testing.T) {
	_, remote, _ := testServer(t, Limits{})
	for _, tc := range []struct {
		name, pin, equivalent, reply string
	}{
		{"expanded-ipv6", "2001:db8:0:0:0:0:0:1", "2001:db8::1", "2001:db8::1"},
		{"compressed-ipv6", "2001:db8::1", "2001:db8:0:0:0:0:0:1", "2001:db8::1"},
		{"uppercase-ipv6", "2001:DB8::ABCD", "2001:db8::abcd", "2001:db8::abcd"},
		{"mapped-ipv4", "::ffff:192.0.2.10", "192.0.2.10", "192.0.2.10"},
		{"ipv4", "192.0.2.10", "::ffff:192.0.2.10", "192.0.2.10"},
		{"hostname", "target.test", "target.test", "target.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, remote, Limits{MaxFlows: 1})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pin := access.Endpoint{Host: tc.pin, Port: 53}
			for association := range 2 {
				p, err := c.OpenPacket(ctx, pin)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				_ = p.SetDeadline(time.Now().Add(4 * time.Second))
				for i, size := range []int{1, 1199, 1200, 0} {
					host := tc.pin
					if i%2 == 0 {
						host = tc.equivalent
					}
					payload := bytes.Repeat([]byte{byte(i + 1)}, size)
					if n, err := p.WriteTo(payload, netaddr.UDP(access.Endpoint{Host: host, Port: 53})); err != nil || n != size {
						t.Fatalf("association %d write %d: %d %v", association, i, n, err)
					}
					b := make([]byte, MaxPayload)
					n, a, err := p.ReadFrom(b)
					if err != nil {
						t.Fatal(err)
					}
					dst, err := netaddr.From(a)
					if err != nil || dst != (access.Endpoint{Host: tc.reply, Port: 53}) || !bytes.Equal(b[:n], payload) {
						t.Fatal("reply bytes or authoritative address changed", dst, err)
					}
					for _, bad := range []access.Endpoint{{Host: tc.pin, Port: 54}, {Host: "2001:db8::2", Port: 53}, {Host: "192.0.2.11", Port: 53}, {Host: "other.test", Port: 53}, {Host: "fe80::1%eth0", Port: 53}, {Host: "2001:db8::g", Port: 53}} {
						if n, err := p.WriteTo([]byte{1}, netaddr.UDP(bad)); n != 0 || !errors.Is(err, ErrProtocol) {
							t.Fatal("fixed target bypass", bad, n, err)
						}
					}
				}
				// Multiple writers use equivalent forms on the same association.
				var wg sync.WaitGroup
				for i := range 8 {
					wg.Go(func() {
						host := tc.pin
						if i%2 == 0 {
							host = tc.equivalent
						}
						if n, err := p.WriteTo(bytes.Repeat([]byte{byte(i)}, 16), netaddr.UDP(access.Endpoint{Host: host, Port: 53})); err != nil || n != 16 {
							t.Error("concurrent write", n, err)
						}
					})
				}
				wg.Wait()
				seen := map[byte]bool{}
				for range 8 {
					var b [32]byte
					n, _, err := p.ReadFrom(b[:])
					if err != nil || n != 16 || b[0] > 7 || seen[b[0]] || !bytes.Equal(b[:n], bytes.Repeat(b[:1], 16)) {
						t.Fatal("concurrent packet boundary/integrity", n, err)
					}
					seen[b[0]] = true
				}
				if _, err := p.WriteTo(make([]byte, 1201), netaddr.UDP(pin)); !errors.Is(err, ErrLimit) {
					t.Fatal("oversize accepted", err)
				}
				p.Close()
			}
		})
	}
}
