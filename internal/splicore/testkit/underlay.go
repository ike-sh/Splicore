package testkit

// This package is imported by tests only. The fixture executes the production
// journal/reconciler and captures actual socket controls without host mutation.
import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/hostnetwork"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
)

type UnderlayEvent struct {
	Scope            underlay.Scope
	Network, Address string
}
type FakeWindowsNetworkBackend struct {
	Removed    chan string
	mu         sync.Mutex
	state      map[string]*hostnetwork.Record
	Events     []UnderlayEvent
	Writes     int
	FailWrite  int
	FailVerify bool
}

func (*FakeWindowsNetworkBackend) Scope() string { return "owned-underlay-runtime-fixture" }
func recordKey(r hostnetwork.Record) string {
	if r.WindowsRoute != nil {
		return "route:" + r.WindowsRoute.Destination
	}
	return r.Kind + ":" + r.Interface + ":" + r.Prefix
}
func clone(r *hostnetwork.Record) *hostnetwork.Record {
	if r == nil {
		return nil
	}
	b, _ := json.Marshal(r)
	var out hostnetwork.Record
	_ = json.Unmarshal(b, &out)
	return &out
}
func (b *FakeWindowsNetworkBackend) Read(_ context.Context, r hostnetwork.Record) (*hostnetwork.Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	current := b.state[recordKey(r)]
	if current != nil && r.WindowsRoute != nil && current.WindowsRoute != nil {
		x, y := *current.WindowsRoute, *r.WindowsRoute
		// Kernel routes do not contain Splicore's reasons/owner metadata. The
		// real native readback validates physical fields then returns the key.
		if x.Destination == y.Destination && x.Index == y.Index && x.InterfaceGUID == y.InterfaceGUID && x.NextHop == y.NextHop && x.Metric == y.Metric {
			return clone(&r), nil
		}
	}
	return clone(current), nil
}
func (b *FakeWindowsNetworkBackend) Write(_ context.Context, r hostnetwork.Record, v *hostnetwork.Record) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Writes++
	if b.Writes == b.FailWrite {
		return errors.New("fixture provisioning failure")
	}
	b.state[recordKey(r)] = clone(v)
	if v == nil && r.WindowsRoute != nil && b.Removed != nil {
		prefix, _ := netip.ParsePrefix(r.WindowsRoute.Destination)
		b.Removed <- prefix.Addr().String()
	}
	return nil
}
func (b *FakeWindowsNetworkBackend) WaitRemoved(ctx context.Context, ip string) error {
	for {
		select {
		case removed := <-b.Removed:
			if removed == ip {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (b *FakeWindowsNetworkBackend) Protect(_ context.Context, s underlay.Scope, n, a string, _ syscall.RawConn) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.FailVerify {
		return errors.New("fixture verification failure")
	}
	b.Events = append(b.Events, UnderlayEvent{s, n, a})
	return nil
}
func (b *FakeWindowsNetworkBackend) Has(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	a := netip.MustParseAddr(ip)
	return b.state["route:"+netip.PrefixFrom(a, a.BitLen()).String()] != nil
}
func (b *FakeWindowsNetworkBackend) Count(p underlay.Purpose) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, e := range b.Events {
		if e.Scope.Purpose == p {
			n++
		}
	}
	return n
}

func (b *FakeWindowsNetworkBackend) SnapshotEvents() []UnderlayEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]UnderlayEvent(nil), b.Events...)
}
func (b *FakeWindowsNetworkBackend) SetFailure(write int, verify bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if write > 0 {
		b.FailWrite = b.Writes + write
	} else {
		b.FailWrite = 0
	}
	b.FailVerify = verify
}
func (b *FakeWindowsNetworkBackend) Corrupt(ip string) {
	b.adjustMetric(ip, 1)
}

// RestoreCorruption is an external fixture owner returning its own mutation.
// Production recovery never overwrites foreign route state.
func (b *FakeWindowsNetworkBackend) RestoreCorruption(ip string) {
	b.adjustMetric(ip, -1)
}
func (b *FakeWindowsNetworkBackend) adjustMetric(ip string, delta int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	a := netip.MustParseAddr(ip)
	r := b.state["route:"+netip.PrefixFrom(a, a.BitLen()).String()]
	if r != nil {
		r.WindowsRoute.Metric = uint32(int(r.WindowsRoute.Metric) + delta)
	}
}

type UnderlayStore struct {
	mu              sync.Mutex
	Data            []byte
	Saves, FailSave int
}

func (s *UnderlayStore) Load() (*hostnetwork.Journal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Data) == 0 {
		return nil, nil
	}
	return hostnetwork.DecodeJournal(s.Data)
}
func (s *UnderlayStore) Save(j *hostnetwork.Journal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Saves++
	if s.Saves == s.FailSave {
		return errors.New("fixture journal failure")
	}
	s.Data, _ = json.Marshal(j)
	return nil
}
func (*UnderlayStore) Close() error { return nil }
func (s *UnderlayStore) FailNext(offset int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if offset > 0 {
		s.FailSave = s.Saves + offset
	} else {
		s.FailSave = 0
	}
}

type UnderlayFixture struct {
	Factory *underlay.Factory
	Host    *hostnetwork.Manager
	Lease   *hostnetwork.Lease
	Backend *FakeWindowsNetworkBackend
	Store   *UnderlayStore
}

func NewUnderlay(t testing.TB) *UnderlayFixture {
	t.Helper()
	b := &FakeWindowsNetworkBackend{state: map[string]*hostnetwork.Record{}, Removed: make(chan string, 1024)}
	s := &UnderlayStore{}
	m, e := hostnetwork.New(b, s)
	if e != nil {
		t.Fatal(e)
	}
	l, e := m.Prepare(context.Background(), []hostnetwork.Record{{Kind: "rule", Family: 4, Priority: 12000, Table: 254, Mark: 1}}, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	guid, _ := identity.NewID()
	w := &underlay.WindowsBackend{Lease: l, Underlays: map[bool]hostnetwork.WindowsUnderlay{true: {InterfaceGUID: guid, Index: 42, NextHop: netip.MustParseAddr("192.0.2.254"), Metric: 100}, false: {InterfaceGUID: guid, Index: 42, NextHop: netip.MustParseAddr("2001:db8::ffff"), Metric: 100}}, SocketControl: b.Protect, Readback: l.Verify}
	f := underlay.NewWithBackend(w)
	t.Cleanup(func() {
		if e := l.Restore(context.Background()); e != nil {
			t.Error(e)
		}
		if e := m.Close(); e != nil {
			t.Error(e)
		}
	})
	return &UnderlayFixture{f, m, l, b, s}
}
