package hostnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type memoryStore struct {
	data        []byte
	saves, fail int
}

func (s *memoryStore) Load() (*Journal, error) {
	if len(s.data) == 0 {
		return nil, nil
	}
	return DecodeJournal(s.data)
}
func (s *memoryStore) Save(j *Journal) error {
	s.saves++
	if s.saves == s.fail {
		return errors.New("synthetic storage fault")
	}
	s.data, _ = json.Marshal(j)
	return nil
}
func (*memoryStore) Close() error { return nil }

type fixtureBackend struct {
	state        map[string]*Record
	writes, fail int
	scope        string
	verifyFault  bool
}

func (b *fixtureBackend) Scope() string {
	if b.scope == "" {
		return "synthetic-local-namespace"
	}
	return b.scope
}
func (b *fixtureBackend) Read(_ context.Context, r Record) (*Record, error) {
	v := cloneRecord(b.state[r.key()])
	if b.verifyFault && b.writes == 1 && v != nil {
		v.Metric++
	}
	return v, nil
}
func (b *fixtureBackend) Write(_ context.Context, key Record, v *Record) error {
	b.writes++
	if b.writes == b.fail {
		return errors.New("synthetic platform fault")
	}
	b.state[key.key()] = cloneRecord(v)
	if v != nil && v.Kind == "interface" {
		b.state[key.key()].Index = 42
	}
	return nil
}
func route(prefix string) Record {
	return Record{Kind: "route", Interface: "synthetic0", Prefix: prefix, Table: 24000, Protocol: 198, Metric: 10}
}
func TestMutationFailuresPreservePreviousState(t *testing.T) {
	for _, fault := range []string{"snapshot-journal", "first-route", "second-route", "applied-journal", "final-journal", "health"} {
		t.Run(fault, func(t *testing.T) {
			b := &fixtureBackend{state: map[string]*Record{}}
			s := &memoryStore{}
			switch fault {
			case "snapshot-journal":
				s.fail = 1
			case "first-route":
				b.fail = 1
			case "second-route":
				b.fail = 2
			case "applied-journal":
				s.fail = 2
			case "final-journal":
				s.fail = 4
			}
			m, err := New(b, s)
			if err != nil {
				t.Fatal(err)
			}
			ready := func() error {
				if fault == "health" {
					return errors.New("synthetic health verification fault")
				}
				return nil
			}
			if _, err = m.Prepare(context.Background(), []Record{route("198.18.0.0/16"), route("198.19.0.0/16")}, ready); err == nil {
				t.Fatal("failure not surfaced")
			}
			for key, value := range b.state {
				if value != nil {
					t.Fatal("partial mutation retained", key)
				}
			}
			if err = m.Recover(context.Background()); err != nil {
				t.Fatal("next start recovery", err)
			}
		})
	}
}
func proxyField(value string) Record {
	return Record{Kind: "proxy", Proxy: &ProxyState{Values: map[string]ProxyValue{"ProxyServer": {Present: true, Type: 1, Text: value}}}}
}
func TestHardCrashRecoveryAndExternalMutationPreserved(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "hard-crash", true: "user-change"}[external], func(t *testing.T) {
			before := proxyField("127.0.0.1:1111")
			after := proxyField("127.0.0.1:2222")
			b := &fixtureBackend{state: map[string]*Record{before.key(): &before}}
			s := &memoryStore{}
			m, err := New(b, s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.Prepare(context.Background(), []Record{after}, nil); err != nil {
				t.Fatal(err)
			}
			if external {
				changed := proxyField("127.0.0.1:3333")
				b.state[changed.key()] = &changed
			}
			// Leave the active journal and host state, as an abrupt process death does.
			_ = m.Close()
			next, err := New(b, s)
			if err != nil {
				t.Fatal(err)
			}
			err = next.Recover(context.Background())
			if external {
				if err == nil || b.state[before.key()].Proxy.Values["ProxyServer"].Text != "127.0.0.1:3333" || next.Status().Recovery != "degraded" {
					t.Fatal("external state overwritten", err)
				}
			} else if err != nil || !equal(b.state[before.key()], &before) || next.Status().ActiveGenerations != 0 {
				t.Fatal("previous proxy not restored", err)
			}
		})
	}
}
func TestPendingWriteRecoveredAndScopeMismatchRefusesMutation(t *testing.T) {
	b := &fixtureBackend{state: map[string]*Record{}}
	s := &memoryStore{}
	m, err := New(b, s)
	if err != nil {
		t.Fatal(err)
	}
	r := route("198.18.0.0/16")
	lease, err := m.Prepare(context.Background(), []Record{r}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Persisted intent is sufficient even if completion acknowledgment was lost.
	m.journal.Generations[0].State = "pending"
	m.journal.Generations[0].Steps[0].State = "pending"
	if err = s.Save(m.journal); err != nil {
		t.Fatal(err)
	}
	b.scope = "different-owned-namespace"
	next, err := New(b, s)
	if err != nil {
		t.Fatal(err)
	}
	writes := b.writes
	if next.Recover(context.Background()) == nil || b.writes != writes {
		t.Fatal("recovery crossed namespace boundary")
	}
	b.scope = ""
	if err = lease.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = next.Recover(context.Background()); err != nil {
		t.Fatal("already restored stale generation", err)
	}
}
func TestPrivateJournalCorruptionAndExclusiveOwnership(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "network")
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := OpenStore(dir); err == nil {
		second.Close()
		t.Fatal("two writers own journal")
	}
	b := &fixtureBackend{state: map[string]*Record{}}
	m, err := New(b, store)
	if err != nil {
		t.Fatal(err)
	}
	l, err := m.Prepare(context.Background(), []Record{route("198.18.0.0/16")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	if err = os.WriteFile(filepath.Join(dir, "journal.json"), []byte(`{"schema":1,"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	broken, err := New(b, store)
	if err == nil || broken.Status().Recovery != "degraded" {
		t.Fatal("corrupt journal accepted")
	}
	writes := b.writes
	if broken.Recover(context.Background()) == nil || writes != b.writes {
		t.Fatal("corruption caused guessed network repair")
	}
}
func TestTenLifecycleRestoresOnlyOwnedResources(t *testing.T) {
	b := &fixtureBackend{state: map[string]*Record{}}
	unrelated := route("203.0.113.0/24")
	b.state[unrelated.key()] = &unrelated
	m, err := New(b, &memoryStore{})
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		l, err := m.Prepare(context.Background(), []Record{route("198.18.0.0/16")}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = l.Restore(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !equal(b.state[unrelated.key()], &unrelated) || m.Status().ActiveGenerations != 0 {
			t.Fatal("unrelated resource changed")
		}
	}
}
func FuzzNetworkJournal(f *testing.F) {
	f.Add([]byte(`{"schema":1,"platform":"linux","scope":"synthetic","generations":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema":1,"schema":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		j, err := DecodeJournal(b)
		if err == nil {
			out, e := json.Marshal(j)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = DecodeJournal(out); e != nil {
				t.Fatal("journal round trip", e)
			}
		}
	})
}

func TestProxyStateSecurityAndAllFieldRestoration(t *testing.T) {
	for range 10 {
		b := &fixtureBackend{state: map[string]*Record{}}
		before := map[string]*Record{}
		for key, value := range map[string]ProxyValue{"ProxyEnable": {Present: true, Type: 4, Number: 0}, "ProxyServer": {Present: true, Type: 1, Text: "http=127.0.0.1:1111;https=127.0.0.1:2222"}, "ProxyOverride": {Present: true, Type: 1, Text: "<local>;owned.test"}, "AutoConfigURL": {Present: true, Type: 1, Text: "https://pac.owned.test/proxy.pac"}, "AutoDetect": {Present: false}} {
			r := Record{Kind: "proxy", Proxy: &ProxyState{Values: map[string]ProxyValue{key: value}}}
			b.state[r.key()] = &r
			before[r.key()] = cloneRecord(&r)
		}
		manager, err := New(b, &memoryStore{})
		if err != nil {
			t.Fatal(err)
		}
		lease, err := manager.Prepare(context.Background(), ProxyPlan("127.0.0.1:3333"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = lease.Restore(context.Background()); err != nil {
			t.Fatal(err)
		}
		for key, record := range before {
			if !equal(b.state[key], record) {
				t.Fatal("proxy state/type/absence not preserved", key)
			}
		}
	}
	for _, value := range []string{"http://user:secret@owned.test", "https://pac.owned.test/p?token=secret", "https://pac.owned.test/p#secret", "bad\x00value"} {
		r := Record{Kind: "proxy", Proxy: &ProxyState{Values: map[string]ProxyValue{"AutoConfigURL": {Present: true, Type: 1, Text: value}}}}
		if r.Validate() == nil {
			t.Fatal("sensitive proxy snapshot accepted")
		}
	}
}

func FuzzSystemProxyRecord(f *testing.F) {
	f.Add([]byte(`{"kind":"proxy","proxy":{"values":{"ProxyEnable":{"present":true,"type":4,"number":1}}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var record Record
		if json.Unmarshal(b, &record) == nil && record.Validate() == nil {
			if record.Kind == "proxy" {
				for _, v := range record.Proxy.Values {
					if !v.Present && (v.Type != 0 || v.Number != 0 || v.Text != "") {
						t.Fatal("absence aliases data")
					}
				}
			}
		}
	})
}

func TestTUNCreateAndDataPlaneFailureCleanupOrdering(t *testing.T) {
	for _, failure := range []string{"create", "ready", "route-after-ready"} {
		t.Run(failure, func(t *testing.T) {
			backend := &fixtureBackend{state: map[string]*Record{}}
			switch failure {
			case "create":
				backend.fail = 1
			case "route-after-ready":
				backend.fail = 3
			}
			manager, err := New(backend, &memoryStore{})
			if err != nil {
				t.Fatal(err)
			}
			plan := []Record{{Kind: "interface", Interface: "synthetic0", MTU: 1500, Addresses: []string{"198.18.0.1/30"}}, {Kind: "address", Interface: "synthetic0", Prefix: "198.18.0.1/30"}, route("0.0.0.0/0")}
			started, stopped := false, false
			ready := func() error {
				started = true
				if failure == "ready" {
					return errors.New("synthetic stack failure")
				}
				return nil
			}
			stop := func() {
				if backend.state["interface:synthetic0"] == nil {
					t.Error("device released before reader stop")
				}
				stopped = true
			}
			if _, err = manager.Prepare(context.Background(), plan, ready, stop); err == nil {
				t.Fatal("fault not surfaced")
			}
			if started && !stopped {
				t.Fatal("reader ownership leaked")
			}
			for _, value := range backend.state {
				if value != nil {
					t.Fatal("partial TUN retained", value.Kind)
				}
			}
		})
	}
}
