package clientruntime

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
)

// Atomic per-connection fixture for runtime/listener ownership tests. The
// multi-call mutation and notification matrix lives in hostnetwork tests.
type proxyRuntimeBackend struct {
	mu     sync.Mutex
	state  hostnetwork.WinINETSnapshot
	writes int
}

func (*proxyRuntimeBackend) Scope() string { return "owned-listener-fixture" }
func (b *proxyRuntimeBackend) Read(_ context.Context, k hostnetwork.Record) (*hostnetwork.Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state
	return &hostnetwork.Record{Kind: "wininet", WinINET: &s}, nil
}
func (b *proxyRuntimeBackend) Write(_ context.Context, k hostnetwork.Record, v *hostnetwork.Record) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = *v.WinINET
	b.writes++
	return nil
}
func (*proxyRuntimeBackend) Transitions(hostnetwork.Record, *hostnetwork.Record, *hostnetwork.Record) ([]*hostnetwork.Record, error) {
	return nil, nil
}
func (*proxyRuntimeBackend) FinalizeRestore(context.Context, hostnetwork.Record) error { return nil }
func (*proxyRuntimeBackend) SystemProxyPlan(s string) ([]hostnetwork.Record, error) {
	return hostnetwork.WinINETPlan(s)
}

type proxyRuntimeStore struct{ data []byte }

func (s *proxyRuntimeStore) Load() (*hostnetwork.Journal, error) {
	if len(s.data) == 0 {
		return nil, nil
	}
	return hostnetwork.DecodeJournal(s.data)
}
func (s *proxyRuntimeStore) Save(j *hostnetwork.Journal) error {
	s.data, _ = json.Marshal(j)
	return nil
}
func (*proxyRuntimeStore) Close() error { return nil }
func TestOwnedProxyListenerFailureRestoresDeterministically(t *testing.T) {
	for _, external := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		m := New()
		before := hostnetwork.WinINETSnapshot{Flags: 13, PAC: "https://pac.fixture.local/a.pac", AutoDiscovery: 1}
		b := &proxyRuntimeBackend{state: before}
		store := &proxyRuntimeStore{}
		manager, e := hostnetwork.New(b, store)
		if e != nil {
			t.Fatal(e)
		}
		m.host = &hostController{manager: manager, platform: hostnetwork.NewPlatform()}
		socket, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		id, _ := identity.NewID()
		state := client.Empty()
		state.Host.SystemProxy = client.SystemProxySettings{Enabled: true, Backend: "wininet", LocalInbound: id}
		state.LocalInbounds = []client.LocalInbound{{ID: id, Name: "fixture", Kind: "http", Listen: access.Endpoint{Host: "127.0.0.1", Port: uint16(socket.Addr().(*net.TCPAddr).Port)}}}
		l := &localListener{spec: state.LocalInbounds[0], socket: socket, done: make(chan struct{})}
		p := &Prepared{m: m, s: &snapshot{state: state}, listeners: map[identity.ID]*localListener{id: l}}
		if e = p.prepareHost(ctx); e != nil {
			t.Fatal(e)
		}
		m.mu.Lock()
		m.host.proxy = p.proxy
		m.host.proxyListener = l
		m.listeners[id] = l
		l.ready.Store(true)
		m.wg.Add(1)
		m.mu.Unlock()
		go m.accept(l)
		if external {
			b.mu.Lock()
			b.state.Server = "external.fixture.local:1234"
			b.mu.Unlock()
		}
		socket.Close()
		select {
		case <-l.done:
		case <-ctx.Done():
			t.Fatal("listener recovery did not complete")
		}
		b.mu.Lock()
		actual := b.state
		b.mu.Unlock()
		if external {
			if actual.Server != "external.fixture.local:1234" || m.HostStatus().Recovery != "degraded" {
				t.Fatal("external proxy overwritten")
			}
		} else {
			if actual != before || m.host.proxy != nil {
				t.Fatal("dead listener retained proxy", actual)
			}
			if e = m.Close(ctx); e != nil {
				t.Fatal(e)
			}
		}
		cancel()
	}
}
func TestProxyUnreadyListenerChangesNoState(t *testing.T) {
	m := New()
	b := &proxyRuntimeBackend{state: hostnetwork.WinINETSnapshot{Flags: 1}}
	manager, e := hostnetwork.New(b, &proxyRuntimeStore{})
	if e != nil {
		t.Fatal(e)
	}
	m.host = &hostController{manager: manager}
	id, _ := identity.NewID()
	state := client.Empty()
	state.Host.SystemProxy = client.SystemProxySettings{Enabled: true, Backend: "wininet", LocalInbound: id}
	state.LocalInbounds = []client.LocalInbound{{ID: id, Name: "fixture", Kind: "mixed", Listen: access.Endpoint{Host: "127.0.0.1", Port: 1080}}}
	p := &Prepared{m: m, s: &snapshot{state: state}, listeners: map[identity.ID]*localListener{}}
	if e = p.prepareHost(context.Background()); e == nil || b.writes != 0 {
		t.Fatal("missing listener changed proxy")
	}
	if _, e = hostnetwork.WinINETPlan(net.JoinHostPort("192.0.2.1", strconv.Itoa(1080))); e == nil {
		t.Fatal("non-loopback proxy accepted")
	}
}
