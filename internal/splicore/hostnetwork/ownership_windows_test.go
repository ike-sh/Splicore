package hostnetwork

import (
	"context"
	"errors"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func TestIncompleteWindowsOwnershipRejectsBeforeMutation(t *testing.T) {
	p := NewPlatform()
	records := ProxyPlan("127.0.0.1:1080")
	records = append(records, Record{Kind: "interface", Interface: "blocked13", Addresses: []string{"198.18.0.1/30"}, MTU: 1500})
	for _, r := range records {
		var typed *identity.Error
		if err := p.Write(context.Background(), r, &r); !errors.As(err, &typed) || typed.Code != identity.NotImplemented {
			t.Fatal("incomplete ownership entered OS mutation", r.Kind, err)
		}
	}
}

func TestWindowsPartialCandidateRetainsExactHandle(t *testing.T) {
	for _, wrongGUID := range []bool{false, true} {
		g, _ := identity.NewID()
		o, _ := identity.NewID()
		guid, _ := identity.NewID()
		id := WindowsAdapterIdentity{GUID: guid, Generation: g, Owner: o}
		driver := &wintunFixtureDriver{adapter: &wintunFixtureAdapter{}, wrongGUID: wrongGUID, failCreate: !wrongGUID, partialCreate: true}
		d, err := createOwnedWintun(driver, "fixture13", id)
		if err == nil || d == nil {
			t.Fatal("partial candidate lost")
		}
		key := Record{Kind: "interface", Interface: "fixture13", Addresses: []string{"198.18.0.1/30"}, MTU: 1500, Adapter: &id}
		p := NewPlatform()
		p.devices[key.Interface] = &windowsWintun{ownedWintun: d, mtu: 1500}
		if err = p.Authorize(Generation{ID: g, Owner: o, Steps: []Step{{Key: key, After: &key, State: "pending"}}}); err != nil {
			t.Fatal(err)
		}
		actual, err := p.Read(context.Background(), key)
		if err != nil || !equal(actual, &key) {
			t.Fatal("partial ownership hidden by OS readback", err)
		}
		driver.adapter.failClose = true
		if err = p.Write(context.Background(), key, nil); err == nil || p.devices[key.Interface] == nil {
			t.Fatal("failed compensation lost handle")
		}
		driver.adapter.failClose = false
		if err = p.Write(context.Background(), key, nil); err != nil || p.devices[key.Interface] != nil || !driver.adapter.closed {
			t.Fatal("exact handle cleanup", err)
		}
	}
}
