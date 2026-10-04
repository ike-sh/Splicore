package hostnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
)

// Models per-connection intent independently from the journal. Writes may fail
// before OR after mutation, notifications may fail, and another actor can edit it.
type winINETFixture struct {
	state          WinINETSnapshot
	events         []uint32
	calls, fail    int
	mutateThenFail bool
	externalAfter  int
}

func (f *winINETFixture) Capture(ctx context.Context) (WinINETSnapshot, error) {
	return f.state, ctx.Err()
}
func (f *winINETFixture) Set(_ context.Context, o uint32, s WinINETSnapshot) error {
	f.calls++
	f.events = append(f.events, o)
	if f.calls == f.fail && !f.mutateThenFail {
		return errors.New("setting failure")
	}
	f.state = winINETNext(f.state, s, o)
	if f.calls == f.externalAfter {
		f.state.Server = "external.local:1234"
	}
	if f.calls == f.fail {
		return errors.New("partial setting failure")
	}
	return nil
}
func (f *winINETFixture) Notify(_ context.Context, o uint32) error {
	f.calls++
	f.events = append(f.events, o)
	if f.calls == f.fail {
		return errors.New("notification failure")
	}
	return nil
}

type winINETFixtureBackend struct {
	api   *winINETFixture
	scope string
}

func (b *winINETFixtureBackend) Scope() string {
	if b.scope != "" {
		return b.scope
	}
	return "fixture-wininet-owner"
}
func (b *winINETFixtureBackend) Read(ctx context.Context, key Record) (*Record, error) {
	s, e := b.api.Capture(ctx)
	return &Record{Kind: key.Kind, WinINET: &s}, e
}
func (b *winINETFixtureBackend) Write(ctx context.Context, key Record, value *Record) error {
	return applyWinINET(ctx, b.api, b.api.state, *value.WinINET)
}
func (b *winINETFixtureBackend) Transitions(key Record, before, after *Record) ([]*Record, error) {
	return winINETRecordTransitions(key, before, after)
}
func (b *winINETFixtureBackend) FinalizeRestore(ctx context.Context, _ Record) error {
	return notifyWinINET(ctx, b.api)
}

func winINETStates() []WinINETSnapshot {
	return []WinINETSnapshot{
		{Flags: 1},
		{Flags: 3, Server: "proxy.local:8080"},
		{Flags: 3, Server: "http=proxy.local:8080;https=proxy.local:8443", Bypass: "<local>;*.fixture.local"},
		{Flags: 5, PAC: "https://pac.fixture.local/a.pac", SecondaryPAC: "https://pac.fixture.local/b.pac", ReloadMinutes: 15},
		{Flags: 9, AutoDiscovery: 3},
		{Flags: 13, PAC: "https://pac.fixture.local/a.pac", AutoDiscovery: 1},
		{Flags: 15, Server: "proxy.local:8080", Bypass: "<local>", PAC: "https://pac.fixture.local/a.pac", AutoDiscovery: 1},
	}
}
func TestWinINETCaptureRestoreMatrix(t *testing.T) {
	ctx := context.Background()
	plan, err := WinINETPlan("127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range winINETStates() {
		t.Run(a.Fingerprint()[:8], func(t *testing.T) {
			f := &winINETFixture{state: a}
			b := &winINETFixtureBackend{api: f}
			s := &memoryStore{}
			m, err := New(b, s)
			if err != nil {
				t.Fatal(err)
			}
			l, err := m.Prepare(ctx, plan, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if f.state != *plan[0].WinINET {
				t.Fatal("wrong applied state", f.state)
			}
			if _, err = DecodeJournal(s.data); err != nil {
				t.Fatal(err)
			}
			if err = l.Restore(ctx); err != nil || f.state != a {
				t.Fatal("restore differs from A", err, f.state, a)
			}
			calls := f.calls
			if err = l.Restore(ctx); err != nil || calls != f.calls {
				t.Fatal("double stop mutated", err)
			}
			for i, o := range f.events {
				if o == 37 && (i == 0 || f.events[i-1] != 39) {
					t.Fatal("notification order", f.events)
				}
			}
		})
	}
}
func TestWinINETEveryFailureWindow(t *testing.T) {
	ctx := context.Background()
	plan, _ := WinINETPlan("[::1]:1080")
	a := winINETStates()[6]
	a.Bypass = "<local>;*.fixture.local"
	a.SecondaryPAC = "https://pac.fixture.local/b.pac"
	a.ReloadMinutes = 15
	for _, after := range []bool{false, true} {
		for failure := 1; failure <= 9; failure++ {
			f := &winINETFixture{state: a, fail: failure, mutateThenFail: after}
			s := &memoryStore{}
			b := &winINETFixtureBackend{api: f}
			m, _ := New(b, s)
			_, err := m.Prepare(ctx, plan, nil)
			if err == nil {
				t.Fatalf("fault %d ignored", failure)
			}
			if f.state != a {
				t.Fatalf("fault %d after=%v leaves unknown state: %+v", failure, after, f.state)
			}
			if err = m.Recover(ctx); err != nil {
				t.Fatal("next start", failure, err)
			}
		}
	}
	for failure := 1; failure <= 3; failure++ {
		f := &winINETFixture{state: a}
		s := &memoryStore{fail: failure}
		m, _ := New(&winINETFixtureBackend{api: f}, s)
		if _, err := m.Prepare(ctx, plan, nil); err == nil {
			t.Fatal("journal fault ignored")
		}
		if f.state != a {
			t.Fatal("journal failure retained mutation")
		}
		if failure == 1 && f.calls != 0 {
			t.Fatal("mutation before durable journal")
		}
	}
}
func TestWinINETCrashPartialAndExternalMutation(t *testing.T) {
	ctx := context.Background()
	a := winINETStates()[6]
	plan, _ := WinINETPlan("127.0.0.1:1080")
	for crash := 0; crash <= 7; crash++ {
		f := &winINETFixture{state: a}
		s := &memoryStore{}
		m, _ := New(&winINETFixtureBackend{api: f}, s)
		_, err := m.Prepare(ctx, plan, nil)
		if err != nil {
			t.Fatal(err)
		}
		states := winINETTransitions(a, *plan[0].WinINET)
		f.state = a
		if crash > 0 {
			f.state = states[min(crash-1, len(states)-1)]
		}
		next, err := New(&winINETFixtureBackend{api: f}, s)
		if err != nil {
			t.Fatal(err)
		}
		if err = next.Recover(ctx); err != nil || f.state != a {
			t.Fatal("partial crash recovery", crash, err)
		}
	}
	for _, during := range []bool{false, true} {
		f := &winINETFixture{state: a}
		if during {
			f.externalAfter = 1
		}
		s := &memoryStore{}
		m, _ := New(&winINETFixtureBackend{api: f}, s)
		l, err := m.Prepare(ctx, plan, nil)
		if during {
			if err == nil {
				t.Fatal("external edit during apply ignored")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			f.state.Server = "external.local:1234"
			err = l.Restore(ctx)
			if err == nil {
				t.Fatal("external edit overwritten")
			}
		}
		if f.state.Server != "external.local:1234" || m.Status().Recovery != "degraded" {
			t.Fatal("external state lost")
		}
		next, e := New(&winINETFixtureBackend{api: f}, s)
		if e != nil {
			t.Fatal(e)
		}
		if next.Recover(ctx) == nil || f.state.Server != "external.local:1234" {
			t.Fatal("restart lost conflict")
		}
	}
}
func TestWinINETRecoveryDebtAndScope(t *testing.T) {
	ctx := context.Background()
	a := winINETStates()[6]
	plan, _ := WinINETPlan("127.0.0.1:1080")
	f := &winINETFixture{state: a}
	s := &memoryStore{}
	b := &winINETFixtureBackend{api: f}
	m, _ := New(b, s)
	l, err := m.Prepare(ctx, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.fail = f.calls + 2
	f.mutateThenFail = true
	if l.Restore(ctx) == nil {
		t.Fatal("restore failure ignored")
	}
	j, err := DecodeJournal(s.data)
	if err != nil || j.Generations[0].State != "conflict" {
		t.Fatal("debt missing", err)
	}
	next, _ := New(&winINETFixtureBackend{api: f, scope: "other-user"}, s)
	before := f.state
	if next.Recover(ctx) == nil || f.state != before {
		t.Fatal("foreign user overwritten")
	}
	f.fail = 0
	next, _ = New(b, s)
	if err = next.Recover(ctx); err != nil || f.state != a {
		t.Fatal("debt not recoverable", err)
	}
}
func TestWinINETReadyFailureAndConcurrentStop(t *testing.T) {
	ctx := context.Background()
	a := winINETStates()[0]
	plan, _ := WinINETPlan("127.0.0.1:1080")
	f := &winINETFixture{state: a}
	s := &memoryStore{}
	m, _ := New(&winINETFixtureBackend{api: f}, s)
	if _, err := m.Prepare(ctx, plan, func() error { return errors.New("listener unavailable") }); err == nil || f.state != a {
		t.Fatal("unready listener changed proxy")
	}
	l, err := m.Prepare(ctx, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := l.Restore(ctx); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if f.state != a {
		t.Fatal("concurrent restoration")
	}
}
func FuzzWinINETSnapshot(f *testing.F) {
	for _, s := range winINETStates() {
		b, _ := json.Marshal(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var s WinINETSnapshot
		if json.Unmarshal(b, &s) != nil || s.Validate() != nil {
			return
		}
		encoded, _ := json.Marshal(s)
		var copy WinINETSnapshot
		if json.Unmarshal(encoded, &copy) != nil || !reflect.DeepEqual(s, copy) || s.Fingerprint() != copy.Fingerprint() {
			t.Fatal("snapshot round trip")
		}
	})
}
