//go:build linux || windows

package hostnetwork

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-tun"
)

type ownedDeviceFixture struct {
	tun.Tun
	closes int
	err    error
}

func (d *ownedDeviceFixture) Close() error {
	d.closes++
	return d.err
}

func TestPartialCandidateDescriptorsReleasedWithoutInterfaceIdentity(t *testing.T) {
	p := NewPlatform()
	first := &ownedDeviceFixture{}
	second := &ownedDeviceFixture{err: errors.New("synthetic close failure")}
	p.devices["candidate0"] = first
	p.devices["candidate1"] = second
	if err := p.CloseOwnedDevice("unowned"); err != nil || first.closes != 0 || second.closes != 0 {
		t.Fatal("unowned name touched a descriptor", err)
	}
	if err := p.CloseOwnedDevice("candidate0"); err != nil || first.closes != 1 {
		t.Fatal("partial candidate not released", err)
	}
	m, err := New(p, &memoryStore{})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); !errors.Is(err, second.err) || second.closes != 1 || p.devices["candidate1"] != second {
		t.Fatal("failed close discarded the owned handle", err)
	}
	second.err = nil
	if err = m.Close(); err != nil || second.closes != 2 || len(p.devices) != 0 {
		t.Fatal("owned close debt not discharged", err)
	}
	if err = m.Close(); err != nil || first.closes != 1 || second.closes != 2 {
		t.Fatal("descriptor closed twice", err)
	}
}
