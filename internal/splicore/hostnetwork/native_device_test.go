//go:build with_gvisor

package hostnetwork

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/nativetun"
)

type nativeDeviceDispatcher struct{}

func (nativeDeviceDispatcher) TCP(context.Context, net.Conn, netip.AddrPort, netip.AddrPort) {}
func (nativeDeviceDispatcher) UDP(context.Context, net.Conn, netip.AddrPort, netip.AddrPort) {}

func TestNativeRuntimeBorrowsWintunUntilJournalRelease(t *testing.T) {
	g, _ := identity.NewID()
	o, _ := identity.NewID()
	driver := &wintunFixtureDriver{adapter: &wintunFixtureAdapter{}}
	d, err := createOwnedWintun(driver, "fixture", WindowsAdapterIdentity{GUID: g, Generation: g, Owner: o})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	r, err := nativetun.New(context.Background(), d, nativetun.Options{MTU: 1500, Dispatcher: nativeDeviceDispatcher{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	<-driver.adapter.session.blocked
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if driver.adapter.closes != 0 || driver.adapter.session.ends != 0 || d.started() {
		t.Fatal("borrower released journal-owned session/adapter or reopened I/O")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if driver.adapter.closes != 1 || driver.adapter.session.ends != 1 {
		t.Fatal("journal did not release exactly once")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}
