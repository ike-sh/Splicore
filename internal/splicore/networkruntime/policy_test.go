package networkruntime

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func httpEndpoint(t *testing.T, s *httptest.Server) access.Endpoint {
	t.Helper()
	u, _ := url.Parse(s.URL)
	a, err := net.ResolveTCPAddr("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	return access.Endpoint{Host: a.IP.String(), Port: uint16(a.Port)}
}
func probeSpec(target string) P.Probe {
	return P.Probe{URL: target, IntervalSeconds: 60, TimeoutSeconds: 2, ExpectedStatus: 204}
}
func TestRealHTTPPolicySelectionAndRecovery(t *testing.T) {
	var requests [3]atomic.Int64
	var unhealthy atomic.Bool
	servers := make([]*httptest.Server, 3)
	dialers := map[identity.ID]ports.ClientDialer{}
	members := []P.Action{}
	for i := range 3 {
		index := i
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests[index].Add(1)
			if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "" {
				t.Error("probe leaked authorization")
			}
			if index == 0 && unhealthy.Load() {
				w.WriteHeader(503)
			} else {
				w.WriteHeader(204)
			}
		}))
		t.Cleanup(servers[i].Close)
		endpoint := httpEndpoint(t, servers[i])
		dialers[testID(i+1)] = &fixtureDialer{endpoint: &endpoint}
		members = append(members, P.Action{Kind: P.Outbound, ID: testID(i + 1)})
	}
	c := P.Config{Groups: []P.PolicyGroup{
		{ID: testID(10), Name: "URL-Test", Type: "url_test", Members: members, URLTest: &P.URLTestSettings{Probe: probeSpec(servers[0].URL)}},
		{ID: testID(11), Name: "Fallback", Type: "fallback", Members: members, Fallback: &P.FallbackSettings{Probe: probeSpec(servers[0].URL)}},
	}}
	e, err := New(c, dialers, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	action := P.Action{Kind: P.Group, ID: testID(10)}
	if _, err = e.Select(action, nil, true, 0); err == nil {
		t.Fatal("unknown active health selected")
	}
	for _, g := range c.Groups {
		for _, a := range members {
			e.probe(context.Background(), g.ID, a)
		}
	}
	// Assert against observed real HTTP latency, preserving configured-order ties.
	expected := members[0]
	best := int64(1 << 62)
	for _, a := range members {
		s := e.memberHealth(e.groups[testID(10)], a)
		if s.State != "healthy" {
			t.Fatal(s)
		}
		if s.LatencyMS < best {
			best = s.LatencyMS
			expected = a
		}
	}
	selected, err := e.Select(action, nil, true, 0)
	if err != nil || selected != expected {
		t.Fatal(selected, expected, err)
	}
	for i := range requests {
		if requests[i].Load() != 2 {
			t.Fatal("not real outbound HTTP", requests[i].Load())
		}
	}
	fallback := P.Action{Kind: P.Group, ID: testID(11)}
	selected, err = e.Select(fallback, nil, true, 0)
	if err != nil || selected != members[0] {
		t.Fatal(selected, err)
	}
	unhealthy.Store(true)
	e.probe(context.Background(), testID(11), members[0])
	selected, err = e.Select(fallback, nil, true, 0)
	if err != nil || selected != members[1] {
		t.Fatal(selected, err)
	}
	unhealthy.Store(false)
	e.probe(context.Background(), testID(11), members[0])
	selected, err = e.Select(fallback, nil, true, 0)
	if err != nil || selected != members[0] {
		t.Fatal(selected, err)
	}
	for _, a := range members {
		e.groups[testID(11)].samples[a] = Sample{State: "unhealthy"}
	}
	if _, err = e.Select(fallback, nil, true, 0); err == nil {
		t.Fatal("all-down silently fell back")
	}
	// Tolerance retains a previous healthy choice; exact ties honor member order.
	g := e.groups[testID(10)]
	g.spec.URLTest.ToleranceMS = 10
	g.selected = members[1]
	g.samples[members[0]] = Sample{State: "healthy", LatencyMS: 10}
	g.samples[members[1]] = Sample{State: "healthy", LatencyMS: 15}
	g.samples[members[2]] = Sample{State: "unhealthy"}
	selected, err = e.Select(action, nil, true, 0)
	if err != nil || selected != members[1] {
		t.Fatal("tolerance", selected, err)
	}
}
func TestRoundRobinConcurrentAffinityPassiveAndInheritance(t *testing.T) {
	members := []P.Action{{Kind: P.Outbound, ID: testID(1)}, {Kind: P.Outbound, ID: testID(2)}}
	c := P.Config{Groups: []P.PolicyGroup{{ID: testID(3), Name: "round robin", Type: "load_balance", Members: members, LoadBalance: &P.LoadBalanceSettings{Algorithm: "round_robin"}}}}
	dialers := map[identity.ID]ports.ClientDialer{testID(1): &fixtureDialer{}, testID(2): &fixtureDialer{}}
	e, err := New(c, dialers, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	// Mutating caller maps/config cannot alter the published engine.
	delete(dialers, testID(1))
	c.Groups[0].Members = append([]P.Action(nil), c.Groups[0].Members...)
	c.Groups[0].Members[0] = P.Action{Kind: P.Reject}
	group := P.Action{Kind: P.Group, ID: testID(3)}
	var distribution [2]atomic.Int64
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for range 100 {
				a, err := e.Select(group, nil, true, 0)
				if err != nil {
					t.Error(err)
					return
				}
				if a == members[0] {
					distribution[0].Add(1)
				} else if a == members[1] {
					distribution[1].Add(1)
				} else {
					t.Error(a)
				}
			}
		})
	}
	wg.Wait()
	if distribution[0].Load() != 1000 || distribution[1].Load() != 1000 {
		t.Fatal(distribution[0].Load(), distribution[1].Load())
	}
	affinity := map[identity.ID]P.Action{}
	fixed, _ := e.Select(group, affinity, true, 0)
	for range 100 {
		a, err := e.Select(group, affinity, true, 0)
		if err != nil || a != fixed {
			t.Fatal("UDP affinity", a, err)
		}
	}
	if got := e.Groups()[0].Selections; got != 2001 {
		t.Fatal("packet reselected", got)
	}
	previous := e.groups[testID(3)]
	previous.samples[members[0]] = Sample{State: "healthy", LastProbe: time.Now(), LatencyMS: 3}
	clone, err := New(e.config, e.dialers, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clone.Close()
	clone.Inherit(e)
	if clone.memberHealth(clone.groups[testID(3)], members[0]).State != "healthy" {
		t.Fatal("unchanged health lost")
	}
	changed := map[identity.ID]ports.ClientDialer{testID(1): &fixtureDialer{}, testID(2): e.dialers[testID(2)]}
	next, err := New(e.config, changed, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	next.Inherit(e)
	if next.memberHealth(next.groups[testID(3)], members[0]).State != "unknown" {
		t.Fatal("stale adapter health inherited")
	}
	passive := Passive{State: "unhealthy", At: time.Now().Add(time.Second)}
	next.passive = func(identity.ID) Passive { return passive }
	next.groups[testID(3)].samples[members[0]] = Sample{State: "healthy", LastProbe: time.Now()}
	if s := next.memberHealth(next.groups[testID(3)], members[0]); s.State != "unhealthy" {
		t.Fatal("new passive failure ignored", s)
	}
	next.groups[testID(3)].samples[members[0]] = Sample{State: "healthy", LastProbe: passive.At.Add(time.Second)}
	if s := next.memberHealth(next.groups[testID(3)], members[0]); s.State != "healthy" {
		t.Fatal("active recovery ignored", s)
	}
}
func TestHealthSchedulerDNSLifecycle10x(t *testing.T) {
	before := runtime.NumGoroutine()
	var count atomic.Int64
	dnsTarget := dnsFixture(t, "udp", answerHandler(&count, "127.0.0.1"), nil)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	for i := range 10 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c := dnsConfig(dnsTarget, "udp")
			c.Groups = []P.PolicyGroup{{ID: testID(2), Name: "health", Type: "fallback", Members: []P.Action{{Kind: P.Direct}}, Fallback: &P.FallbackSettings{Probe: probeSpec(target.URL)}}}
			e, err := New(c, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					e.Start()
					for range 10 {
						_, _ = e.Lookup(context.Background(), "lifecycle.test")
						_ = e.Groups()
						e.FlushCache()
						_ = e.Matcher.Match(Query{Domain: "lifecycle.test"}, P.Action{Kind: P.Direct}, true)
					}
				})
			}
			wg.Wait()
			e.StopScheduler()
			e.Close()
			if _, _, err := e.owner.Begin(context.Background()); err == nil {
				t.Fatal("closed DNS owner admitted work")
			}
		})
	}
	// Fixtures still own a bounded number of goroutines; all engine jobs have joined.
	if growth := runtime.NumGoroutine() - before; growth > 8 {
		t.Fatal("unbounded goroutine growth", growth)
	}
}
func TestConcurrentStartAndShutdown(t *testing.T) {
	entered := make(chan struct{}, 8)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	defer target.Close()
	c := P.Config{Groups: []P.PolicyGroup{{ID: testID(1), Name: "blocked probe", Type: "fallback", Members: []P.Action{{Kind: P.Direct}}, Fallback: &P.FallbackSettings{Probe: probeSpec(target.URL)}}}}
	e, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Start()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("probe never reached local fixture")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { e.Start(); e.StopScheduler(); e.Close() })
	}
	wg.Wait()
	if e.scheduleCtx.Err() == nil {
		t.Fatal("scheduler not canceled")
	}
}

func TestBoundedSchedulerWorkersAndInvalidConstructor(t *testing.T) {
	var active, peak atomic.Int64
	entered := make(chan struct{}, 8)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer target.Close()
	members := []P.Action{}
	dialers := map[identity.ID]ports.ClientDialer{}
	for i := range 64 {
		id := testID(i + 1)
		members = append(members, P.Action{Kind: P.Outbound, ID: id})
		dialers[id] = &fixtureDialer{}
	}
	c := P.Config{Groups: []P.PolicyGroup{{ID: testID(100), Name: "bounded", Type: "fallback", Members: members, Fallback: &P.FallbackSettings{Probe: probeSpec(target.URL)}}}}
	e, err := New(c, dialers, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Start()
	for range 4 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("workers not started")
		}
	}
	e.Close()
	if peak.Load() != 4 {
		t.Fatal("scheduler concurrency", peak.Load())
	}
	bad := c.Clone()
	bad.Groups[0].Fallback = nil
	if _, err := New(bad, dialers, nil); err == nil {
		t.Fatal("invalid typed group reached runtime")
	}
	bad = c.Clone()
	a := P.Action{Kind: P.Group, ID: testID(100)}
	bad.Groups[0].Members = []P.Action{a}
	if _, err := New(bad, dialers, nil); err == nil {
		t.Fatal("cycle reached runtime")
	}
}
