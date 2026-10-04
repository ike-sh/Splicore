package underlay_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/hostnetwork"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
)

func scope(p underlay.Purpose) underlay.Scope {
	id, _ := identity.NewID()
	return underlay.Scope{Purpose: p, Runtime: id}
}
func TestUnderlaySharedReferencesRetirementAndCrash(t *testing.T) {
	ctx := context.Background()
	x := testkit.NewUnderlay(t)
	f := x.Factory
	a, e := f.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	b, e := f.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	dns, e := f.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	ip := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	for _, v := range []struct {
		l *underlay.Lease
		p underlay.Purpose
	}{{a, underlay.ProxyUnderlay}, {b, underlay.ProxyUnderlay}, {dns, underlay.DNSBootstrap}} {
		if e = v.l.AddEndpoint(ctx, scope(v.p), ip); e != nil {
			t.Fatal(e)
		}
	}
	if e = a.Close(); e != nil {
		t.Fatal(e)
	}
	if e = a.Close(); e != nil {
		t.Fatal(e)
	}
	if !x.Backend.Has("192.0.2.1") {
		t.Fatal("shared protection released by A")
	}
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	if !x.Backend.Has("192.0.2.1") {
		t.Fatal("DNS reference lost")
	}
	if e = dns.Close(); e != nil {
		t.Fatal(e)
	}
	if x.Backend.Has("192.0.2.1") {
		t.Fatal("last reference leaked")
	}
	stale, e := f.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	if e = stale.AddEndpoint(ctx, scope(underlay.ProxyUnderlay), ip); e != nil {
		t.Fatal(e)
	}
	// Reconstructed control metadata starts empty: no imaginary socket refs.
	recovered, e := hostnetwork.New(x.Backend, x.Store)
	if e != nil {
		t.Fatal(e)
	}
	if e = recovered.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	if x.Backend.Has("192.0.2.1") {
		t.Fatal("stale generation survived crash recovery")
	}
	if e = x.Lease.Restore(ctx); e != nil {
		t.Fatal(e)
	}
	if e = recovered.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestUnderlayProvisionFailureAndVerification(t *testing.T) {
	ctx := context.Background()
	x := testkit.NewUnderlay(t)
	old, e := x.Factory.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	if e = old.AddEndpoint(ctx, scope(underlay.ProxyUnderlay), []netip.Addr{netip.MustParseAddr("192.0.2.1")}); e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"write"} {
		t.Run(fault, func(t *testing.T) {
			candidate, e := x.Factory.Begin(ctx, true)
			if e != nil {
				t.Fatal(e)
			}
			if fault == "write" {
				x.Backend.SetFailure(2, false)
			} else {
				x.Store.FailNext(2)
			}
			e = candidate.AddEndpoint(ctx, scope(underlay.ProxyUnderlay), []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")})
			if e == nil {
				t.Fatal("fault accepted")
			}
			x.Backend.SetFailure(0, false)
			x.Store.FailNext(0)
			if !x.Backend.Has("192.0.2.1") || x.Backend.Has("192.0.2.2") || x.Backend.Has("192.0.2.3") {
				t.Fatal("candidate changed committed protections")
			}
			if e = candidate.Close(); e != nil {
				t.Fatal(e)
			}
		})
	}
	if e = old.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = underlay.FromContext(ctx); e == nil {
		t.Fatal("missing capability accepted")
	}
	if _, e = underlay.Normalize(nil); e == nil {
		t.Fatal("empty resolution accepted")
	}
	for _, ip := range []string{"0.0.0.0", "ff02::1", "::ffff:0.0.0.0"} {
		if _, e = underlay.Normalize([]netip.Addr{netip.MustParseAddr(ip)}); e == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
	if e = old.AddEndpoint(ctx, scope(underlay.ProxyUnderlay), []netip.Addr{netip.MustParseAddr("192.0.2.4")}); e == nil {
		t.Fatal("retired generation accepted")
	}
	if e = (&underlay.Lease{}).Close(); e == nil {
		t.Fatal("unknown lease accepted")
	}
	child, e := x.Factory.AcquireChild()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = x.Factory.Begin(ctx, true); e == nil {
		t.Fatal("unprotected child allowed TUN activation")
	}
	child.Close()
	child.Close()
}

func TestUnderlaySocketControlConcurrencyAndNoTUN(t *testing.T) {
	ctx := context.Background()
	x := testkit.NewUnderlay(t)
	s := scope(underlay.DirectEgress)
	d, e := x.Factory.New(s)
	if e != nil {
		t.Fatal(e)
	}
	p, e := d.ListenPacket(ctx, "udp4", "127.0.0.1:0", "192.0.2.1:53")
	if e != nil {
		t.Fatal(e)
	}
	p.Close()
	if x.Backend.Count(underlay.DirectEgress) != 0 {
		t.Fatal("no-TUN modified host/socket state")
	}
	l, e := x.Factory.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, e := d.ListenPacket(ctx, "udp4", "127.0.0.1:0", "192.0.2.1:53")
			if e != nil {
				t.Error(e)
				return
			}
			p.Close()
		}()
	}
	wg.Wait()
	if x.Backend.Count(underlay.DirectEgress) != 20 {
		t.Fatal("packet control bypassed")
	}
	local, _ := x.Factory.New(scope(underlay.LocalControl))
	if _, e = local.DialContext(ctx, "tcp4", "192.0.2.1:1"); e == nil {
		t.Fatal("non-local control accepted")
	}
	// Windows System APIs may issue sockets outside net.Resolver.Dial.
	if _, e = d.LookupNetIP(ctx, "ip", "fixture.invalid"); e == nil {
		t.Fatal("unsafe System resolver accepted")
	}
	if e = l.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestUnderlayJournalFailureRetainsOldRoutesAndDebt(t *testing.T) {
	x := testkit.NewUnderlay(t)
	ctx := context.Background()
	old, e := x.Factory.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	if e = old.AddEndpoint(ctx, scope(underlay.ProxyUnderlay), []netip.Addr{netip.MustParseAddr("192.0.2.1")}); e != nil {
		t.Fatal(e)
	}
	candidate, e := x.Factory.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	x.Store.FailNext(2)
	if e = candidate.AddEndpoint(ctx, scope(underlay.ProxyUnderlay), []netip.Addr{netip.MustParseAddr("192.0.2.2")}); e == nil {
		t.Fatal("journal failure ignored")
	}
	if !x.Backend.Has("192.0.2.1") || x.Backend.Has("192.0.2.2") {
		t.Fatal("old resources changed")
	}
	if x.Factory.Status().Health != "degraded" || x.Host.Status().Recovery != "degraded" {
		t.Fatal("cleanup debt not reported")
	}
	x.Store.FailNext(0)
	// Explicit process retirement/recovery, never fake old socket references.
	if e = x.Host.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	if x.Backend.Has("192.0.2.1") {
		t.Fatal("recovery leaked stale protection")
	}
}

func FuzzUnderlayResolvedSet(f *testing.F) {
	f.Add("192.0.2.1")
	f.Add("::ffff:192.0.2.1")
	f.Add("::")
	f.Fuzz(func(t *testing.T, s string) {
		a, e := netip.ParseAddr(s)
		if e != nil {
			return
		}
		first, e := underlay.Normalize([]netip.Addr{a, a})
		if e != nil {
			return
		}
		second, e := underlay.Normalize(first)
		if e != nil || len(first) != 1 || len(second) != 1 || first[0] != second[0] {
			t.Fatal("normalization not stable")
		}
	})
}

func TestUnderlaySocketFailureAndExternalMutationFailClosed(t *testing.T) {
	for _, fault := range []string{"socket", "external-route"} {
		t.Run(fault, func(t *testing.T) {
			x := testkit.NewUnderlay(t)
			ctx := context.Background()
			l, err := x.Factory.Begin(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			if err = l.AddEndpoint(ctx, scope(underlay.ProxyUnderlay), []netip.Addr{netip.MustParseAddr("192.0.2.1")}); err != nil {
				t.Fatal(err)
			}
			if fault == "socket" {
				x.Backend.SetFailure(0, true)
			} else {
				x.Backend.Corrupt("192.0.2.1")
			}
			d, _ := x.Factory.New(scope(underlay.DirectEgress))
			if p, err := d.ListenPacket(ctx, "udp4", "127.0.0.1:0", "192.0.2.1:53"); err == nil {
				p.Close()
				t.Fatal("failed protection admitted socket")
			}
			if x.Factory.Status().Health != "degraded" {
				t.Fatal("failed protection reported healthy")
			}
			if _, err = x.Factory.Begin(ctx, true); err == nil {
				t.Fatal("degraded protection admitted generation")
			}
			// External mutation is preserved by exact-match restoration.
			x.Backend.SetFailure(0, false)
			if err = l.Close(); err != nil && fault == "socket" {
				t.Fatal(err)
			}
			if fault == "external-route" && !x.Backend.Has("192.0.2.1") {
				t.Fatal("foreign mutation removed")
			}
			if fault == "external-route" {
				x.Backend.RestoreCorruption("192.0.2.1")
				if err = x.Host.Recover(ctx); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
