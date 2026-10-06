package networkruntime

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Sample struct {
	State     string    `json:"state"`
	LastProbe time.Time `json:"last_probe"`
	LatencyMS int64     `json:"latency_ms"`
	Error     string    `json:"last_error,omitempty"`
}
type Passive struct {
	State string
	At    time.Time
}
type groupState struct {
	spec       P.PolicyGroup
	mu         sync.Mutex
	samples    map[P.Action]Sample
	selected   P.Action
	next       atomic.Uint64
	selections atomic.Int64
}
type Engine struct {
	underlay                                    *underlay.Factory
	generation                                  identity.ID
	config                                      P.Config
	Matcher                                     *Matcher
	dialers                                     map[identity.ID]ports.ClientDialer
	passive                                     func(identity.ID) Passive
	groups                                      map[identity.ID]*groupState
	owner                                       *clientio.Owner
	scheduleCtx                                 context.Context
	cancelSchedule                              context.CancelFunc
	started                                     sync.Once
	stopped                                     sync.Once
	closed                                      sync.Once
	wg                                          sync.WaitGroup
	lifecycleMu                                 sync.Mutex
	dnsMu                                       sync.Mutex
	cache                                       *dnsCache
	bindings                                    map[netip.Addr]dnsBinding
	dnsCounts                                   map[identity.ID]*dnsCounters
	dnsQueries, dnsHits, dnsMisses, dnsFailures atomic.Int64
}

func New(c P.Config, dialers map[identity.ID]ports.ClientDialer, passive func(identity.ID) Passive, locals ...identity.ID) (*Engine, error) {
	return NewWithUnderlay(underlay.New(), "", c, dialers, passive, locals...)
}
func NewWithUnderlay(f *underlay.Factory, generation identity.ID, c P.Config, dialers map[identity.ID]ports.ClientDialer, passive func(identity.ID) Passive, locals ...identity.ID) (*Engine, error) {
	if _, err := f.New(underlay.Scope{Purpose: underlay.DNSBootstrap, Generation: generation}); err != nil {
		return nil, err
	}
	outIDs, inIDs := map[identity.ID]bool{}, map[identity.ID]bool{}
	owned := make(map[identity.ID]ports.ClientDialer, len(dialers))
	for id, d := range dialers {
		outIDs[id] = true
		owned[id] = d
	}
	for _, id := range locals {
		inIDs[id] = true
	}
	if err := c.Validate(outIDs, inIDs); err != nil {
		return nil, err
	}
	m, err := Compile(c)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{config: c.Clone(), Matcher: m, dialers: owned, passive: passive, groups: map[identity.ID]*groupState{}, owner: clientio.New(), scheduleCtx: ctx, cancelSchedule: cancel, dnsCounts: map[identity.ID]*dnsCounters{}, cache: newDNSCache(c.DNS.Cache.Capacity)}
	e.underlay = f
	e.generation = generation
	for _, g := range e.config.Groups {
		e.groups[g.ID] = &groupState{spec: g, samples: map[P.Action]Sample{}}
	}
	for _, s := range e.config.Servers {
		e.dnsCounts[s.ID] = &dnsCounters{}
	}
	return e, nil
}
func unavailable() error {
	return identity.Err(identity.Unavailable, "policy group has no available member")
}
func (e *Engine) memberHealth(g *groupState, a P.Action) Sample {
	g.mu.Lock()
	s, exists := g.samples[a]
	g.mu.Unlock()
	if !exists {
		s.State = "unknown"
	}
	if a.Kind == P.Reject {
		s.State = "unhealthy"
		return s
	}
	if a.Kind == P.Outbound && e.passive != nil {
		p := e.passive(a.ID)
		if p.State == "unhealthy" && (s.State == "unknown" || p.At.After(s.LastProbe)) {
			s.State = "unhealthy"
			s.Error = "outbound_connection_failed"
		} else if s.State == "unknown" && p.State == "healthy" && g.spec.Probe() == nil {
			s.State = "healthy"
		}
	}
	if a.Kind == P.Group {
		if _, err := e.Select(a, nil, false, 0); err != nil {
			s.State = "unhealthy"
		}
	}
	if g.spec.Probe() == nil && a.Kind == P.Direct {
		s.State = "healthy"
	}
	return s
}

// affinity is private to one SOCKS UDP association. Explain peeks without counters or I/O.
func (e *Engine) Select(a P.Action, affinity map[identity.ID]P.Action, count bool, depth int) (P.Action, error) {
	if depth > 8 {
		return P.Action{}, unavailable()
	}
	if a.Kind != P.Group {
		if a.Kind == P.Outbound && e.dialers[a.ID] == nil {
			return P.Action{}, unavailable()
		}
		return a, nil
	}
	if affinity != nil {
		if fixed, ok := affinity[a.ID]; ok {
			return fixed, nil
		}
	}
	g := e.groups[a.ID]
	if g == nil {
		return P.Action{}, unavailable()
	}
	spec := g.spec
	var chosen P.Action
	switch spec.Type {
	case "selector":
		chosen = spec.Selector.Selected
		if e.memberHealth(g, chosen).State == "unhealthy" {
			return P.Action{}, unavailable()
		}
	case "fallback":
		for _, m := range spec.Members {
			if e.memberHealth(g, m).State == "healthy" {
				chosen = m
				break
			}
		}
	case "url_test":
		best := int64(1 << 62)
		for _, m := range spec.Members {
			s := e.memberHealth(g, m)
			if s.State == "healthy" && s.LatencyMS < best {
				best = s.LatencyMS
				chosen = m
			}
		}
		g.mu.Lock()
		previous := g.selected
		g.mu.Unlock()
		if previous.Kind != "" {
			s := e.memberHealth(g, previous)
			if s.State == "healthy" && s.LatencyMS <= best+int64(spec.URLTest.ToleranceMS) {
				chosen = previous
			}
		}
	case "load_balance":
		candidates := []P.Action{}
		for _, m := range spec.Members {
			s := e.memberHealth(g, m)
			if s.State == "healthy" || spec.Probe() == nil && s.State == "unknown" {
				candidates = append(candidates, m)
			}
		}
		if len(candidates) > 0 {
			index := g.next.Load()
			if count {
				index = g.next.Add(1) - 1
			}
			chosen = candidates[index%uint64(len(candidates))]
		}
	}
	if chosen.Kind == "" {
		return P.Action{}, unavailable()
	}
	terminal, err := e.Select(chosen, affinity, count, depth+1)
	if err != nil {
		return P.Action{}, err
	}
	if count {
		g.selections.Add(1)
		g.mu.Lock()
		g.selected = chosen
		g.mu.Unlock()
	}
	if affinity != nil {
		affinity[a.ID] = terminal
	}
	return terminal, nil
}
func (e *Engine) Explain(q Query, fallback P.Action, count bool, affinity map[identity.ID]P.Action) (Explanation, error) {
	if err := q.Validate(); err != nil {
		return Explanation{}, err
	}
	out := e.Matcher.Match(q, fallback, count)
	if out.Action.Kind == P.Group {
		out.Group = out.Action.ID
	}
	selected, err := e.Select(out.Action, affinity, count, 0)
	out.Selected = selected
	out.Available = err == nil && selected.Kind != P.Reject
	return out, err
}

type MemberStatus struct {
	Member P.Action `json:"member"`
	Health Sample   `json:"health"`
}
type GroupStatus struct {
	ID         identity.ID    `json:"id"`
	Selected   P.Action       `json:"selected"`
	Selections int64          `json:"selection_count,string"`
	Members    []MemberStatus `json:"members"`
	Available  bool           `json:"available"`
}

func (e *Engine) Groups() []GroupStatus {
	out := []GroupStatus{}
	for _, spec := range e.config.Groups {
		g := e.groups[spec.ID]
		selected, err := e.Select(P.Action{Kind: P.Group, ID: spec.ID}, nil, false, 0)
		v := GroupStatus{ID: spec.ID, Selected: selected, Selections: g.selections.Load(), Members: []MemberStatus{}, Available: err == nil}
		for _, m := range spec.Members {
			v.Members = append(v.Members, MemberStatus{m, e.memberHealth(g, m)})
		}
		out = append(out, v)
	}
	return out
}
func (e *Engine) Inherit(previous *Engine) {
	if previous == nil {
		return
	}
	if reflect.DeepEqual(e.config.DNS, previous.config.DNS) && reflect.DeepEqual(e.config.Servers, previous.config.Servers) && reflect.DeepEqual(e.config.DNSRules, previous.config.DNSRules) {
		previous.dnsMu.Lock()
		e.bindings = map[netip.Addr]dnsBinding{}
		for ip, b := range previous.bindings {
			e.bindings[ip] = b
		}
		previous.dnsMu.Unlock()
	}
	for id, g := range e.groups {
		old := previous.groups[id]
		if old == nil {
			continue
		}
		if !e.sameGroup(previous, id, map[identity.ID]bool{}) {
			continue
		}
		old.mu.Lock()
		for a, s := range old.samples {
			g.samples[a] = s
		}
		g.selected = old.selected
		old.mu.Unlock()
		g.next.Store(old.next.Load())
		g.selections.Store(old.selections.Load())
	}
}

// Samples may be inherited only when every reachable adapter and group is unchanged.
func (e *Engine) sameGroup(previous *Engine, id identity.ID, checked map[identity.ID]bool) bool {
	if checked[id] {
		return true
	}
	checked[id] = true
	g, old := e.groups[id], previous.groups[id]
	if g == nil || old == nil || effectiveGroup(g.spec) != effectiveGroup(old.spec) {
		return false
	}
	for _, a := range g.spec.Members {
		if a.Kind == P.Group && !e.sameGroup(previous, a.ID, checked) {
			return false
		}
		if a.Kind == P.Outbound {
			x, y := reflect.ValueOf(e.dialers[a.ID]), reflect.ValueOf(previous.dialers[a.ID])
			if !x.IsValid() || !y.IsValid() || !x.Comparable() || !y.Comparable() || !x.Equal(y) {
				return false
			}
		}
	}
	return true
}
func (e *Engine) Start() {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.started.Do(func() {
		if e.scheduleCtx.Err() != nil {
			return
		}
		hasProbe := false
		for _, g := range e.config.Groups {
			hasProbe = hasProbe || g.Probe() != nil
		}
		if !hasProbe {
			return
		}
		jobs := make(chan struct {
			group  identity.ID
			member P.Action
		}, 16)
		for range 4 {
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				for {
					select {
					case <-e.scheduleCtx.Done():
						return
					case job, ok := <-jobs:
						if !ok {
							return
						}
						e.probe(e.scheduleCtx, job.group, job.member)
					}
				}
			}()
		}
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer close(jobs)
			next := map[identity.ID]time.Time{}
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				now := time.Now()
				for _, g := range e.config.Groups {
					p := g.Probe()
					if p == nil || now.Before(next[g.ID]) {
						continue
					}
					next[g.ID] = now.Add(time.Duration(p.IntervalSeconds) * time.Second)
					for _, m := range g.Members {
						select {
						case jobs <- struct {
							group  identity.ID
							member P.Action
						}{g.ID, m}:
						case <-e.scheduleCtx.Done():
							return
						}
					}
				}
				select {
				case <-e.scheduleCtx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	})
}
func (e *Engine) StopScheduler() {
	e.stopped.Do(func() { e.lifecycleMu.Lock(); e.cancelSchedule(); e.lifecycleMu.Unlock(); e.wg.Wait() })
}
func (e *Engine) Close() { e.closed.Do(func() { e.StopScheduler(); e.owner.Close(); e.FlushCache() }) }
func (e *Engine) probe(ctx context.Context, id identity.ID, member P.Action) {
	g := e.groups[id]
	p := g.spec.Probe()
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()
	start := time.Now()
	sample := Sample{State: "unhealthy", LastProbe: start, Error: "probe_failed"}
	terminal, err := e.Select(member, nil, false, 0)
	if err == nil && terminal.Kind != P.Reject {
		u, _ := url.Parse(p.URL)
		port := uint16(80)
		if u.Scheme == "https" {
			port = 443
		}
		if u.Port() != "" {
			n, _ := strconv.Atoi(u.Port())
			port = uint16(n)
		}
		endpoint := access.Endpoint{Host: u.Hostname(), Port: port}
		if _, parseErr := netip.ParseAddr(endpoint.Host); parseErr != nil {
			var addresses []netip.Addr
			addresses, err = e.Bootstrap(ctx, endpoint.Host)
			if err == nil && len(addresses) > 0 {
				endpoint.Host = addresses[0].String()
			} else if err == nil {
				err = unavailable()
			}
		}
		if err == nil {
			transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return e.dialPurpose(ctx, terminal, "tcp", endpoint, underlay.HealthProbe)
			}}
			defer transport.CloseIdleConnections()
			client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
			var response *http.Response
			response, err = client.Do(req)
			if err == nil {
				_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4097))
				_ = response.Body.Close()
				if err == nil && response.StatusCode == p.ExpectedStatus {
					sample.State = "healthy"
					sample.Error = ""
					sample.LatencyMS = time.Since(start).Milliseconds()
				}
			}
		}
	}
	sample.LastProbe = time.Now()
	if ctx.Err() != nil {
		sample.Error = "probe_timeout_or_canceled"
	}
	g.mu.Lock()
	g.samples[member] = sample
	g.mu.Unlock()
}
