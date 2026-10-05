package application

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/nodeimport"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/remotesource"
	"slices"
	"sync"
	"time"
)

type managementState struct {
	schedulerMu    sync.Mutex
	plans          map[identity.ID]*managementPlan // client.mu
	mu             sync.Mutex
	slots          chan struct{}
	busy           map[identity.ID]bool
	active         int
	changed        chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc
	scheduleCancel context.CancelFunc
	scheduleDone   chan struct{}
	stopped        bool
}

type providerRefreshError struct {
	code     string
	err      error
	revision identity.Revision // committed snapshot observed before this request's I/O
}

func (e *providerRefreshError) Error() string { return e.err.Error() }
func (e *providerRefreshError) Unwrap() error { return e.err }
func providerFailureCode(err error, fallback string) string {
	var phase *providerRefreshError
	if errors.As(err, &phase) {
		return phase.code
	}
	var domain *identity.Error
	if errors.As(err, &domain) && domain.Code == identity.Conflict {
		return "revision_changed"
	}
	return fallback
}

func newManagementState() *managementState {
	ctx, cancel := context.WithCancel(context.Background())
	return &managementState{plans: map[identity.ID]*managementPlan{}, slots: make(chan struct{}, 4), busy: map[identity.ID]bool{}, changed: make(chan struct{}), ctx: ctx, cancel: cancel}
}
func (m *managementState) notify() { close(m.changed); m.changed = make(chan struct{}) }
func (s *Service) acquireRefresh(ctx context.Context, id identity.ID) (context.Context, func(), error) {
	if s.client == nil || id.Validate() != nil {
		return nil, nil, managementInvalid()
	}
	m := s.client.management
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return nil, nil, identity.Err(identity.Unavailable, "provider management stopped")
	}
	m.active++
	m.mu.Unlock()
	releaseActive := func() { m.mu.Lock(); m.active--; m.notify(); m.mu.Unlock() }
	merged, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	finish := func() { stop(); cancel(); releaseActive() }
	select {
	case m.slots <- struct{}{}:
	case <-merged.Done():
		finish()
		return nil, nil, identity.Err(identity.Unavailable, "provider refresh canceled")
	}
	for {
		m.mu.Lock()
		if !m.busy[id] {
			m.busy[id] = true
			m.mu.Unlock()
			break
		}
		changed := m.changed
		m.mu.Unlock()
		select {
		case <-changed:
		case <-merged.Done():
			<-m.slots
			finish()
			return nil, nil, identity.Err(identity.Unavailable, "provider refresh canceled")
		}
	}
	return merged, func() {
		m.mu.Lock()
		delete(m.busy, id)
		m.notify()
		m.mu.Unlock()
		<-m.slots
		finish()
	}, nil
}
func (s *Service) PreviewProviderRefresh(ctx context.Context, id identity.ID) (ManagementPreview, error) {
	ctx, done, e := s.acquireRefresh(ctx, id)
	if e != nil {
		return ManagementPreview{}, e
	}
	defer done()
	return s.previewProviderRefresh(ctx, id)
}
func (s *Service) RefreshProvider(ctx context.Context, id identity.ID) (ClientResult, error) {
	ctx, done, e := s.acquireRefresh(ctx, id)
	if e != nil {
		return ClientResult{}, e
	}
	defer done()
	p, e := s.previewProviderRefresh(ctx, id)
	if e != nil {
		var observed *providerRefreshError
		if errors.As(e, &observed) {
			s.recordProviderFailure(ctx, id, providerFailureCode(e, "validation_failed"), observed.revision)
		}
		return ClientResult{}, e
	}
	if !p.Applicable {
		code := "validation_failed"
		if p.Reason == "safety_guard" {
			code = "safety_guard"
		}
		s.recordProviderFailure(ctx, id, code, p.Revision)
		return ClientResult{}, identity.Err(identity.Invalid, "provider refresh rejected")
	}
	result, e := s.ApplyManagement(ctx, ManagementApply{p.Token, p.Revision})
	if e != nil {
		s.recordProviderFailure(ctx, id, providerFailureCode(e, "apply_failed"), p.Revision)
	}
	return result, e
}
func (s *Service) previewProviderRefresh(ctx context.Context, id identity.ID) (ManagementPreview, error) {
	c := s.client
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ManagementPreview{}, identity.Err(identity.Unavailable, "client runtime closed")
	}
	state, e := c.repo.ClientState(ctx)
	if e != nil {
		c.mu.Unlock()
		return ManagementPreview{}, e
	}
	pos := slices.IndexFunc(state.Management.Providers, func(p provider.Provider) bool { return p.ID == id })
	if pos < 0 {
		c.mu.Unlock()
		return ManagementPreview{}, identity.Err(identity.NotFound, "provider not found")
	}
	p := state.Management.Providers[pos]
	repo, ok := c.repo.(ports.ProviderRepository)
	if !ok {
		c.mu.Unlock()
		return ManagementPreview{}, identity.Err(identity.Unavailable, "provider storage unavailable")
	}
	source, e := repo.RevealProviderSource(ctx, id)
	if e != nil {
		c.mu.Unlock()
		return ManagementPreview{}, e
	}
	network, e := c.manager.OpenFetch(ctx, p.FetchAction)
	c.mu.Unlock()
	if e != nil {
		return ManagementPreview{}, e
	}
	fetched, e := remotesource.Fetch(ctx, network, p, source)
	closeErr := network.Close()
	if e != nil {
		return ManagementPreview{}, &providerRefreshError{code: "fetch_failed", err: e, revision: state.Revision}
	}
	if closeErr != nil {
		return ManagementPreview{}, identity.Err(identity.Unavailable, "provider network cleanup failed")
	}
	defer clear(fetched.Body)
	// Parse before reacquiring the application control lock. No data path lock is held.
	var parsed nodeimport.Result
	var rules []P.RuleMatch
	if !fetched.NotModified {
		if p.Kind == "proxy" {
			parsed, e = nodeimport.Parse(p.Format, fetched.Body)
		} else {
			rules, e = nodeimport.ParseRules(p.Format, fetched.Body)
		}
		if e != nil {
			return ManagementPreview{}, &providerRefreshError{code: "parse_failed", err: e, revision: state.Revision}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ManagementPreview{}, identity.Err(identity.Unavailable, "client runtime closed")
	}
	current, e := c.repo.ClientState(ctx)
	if e != nil {
		return ManagementPreview{}, e
	}
	if current.Revision != state.Revision {
		return ManagementPreview{}, identity.RevisionConflict(current.Revision)
	}
	plan := newManagementPlan(current)
	plan.preview.ProviderID = id
	plan.preview.Generation = p.Generation
	plan.preview.NotModified = fetched.NotModified
	if !fetched.NotModified {
		if p.Kind == "proxy" {
			if e = s.diffNodes(ctx, plan, parsed, &p, p.Mode, p.GenerateOutbounds, p.Engine); e != nil {
				return ManagementPreview{}, e
			}
		} else {
			if len(rules) == 0 {
				plan.preview.Applicable = false
				plan.preview.Reason = "safety_guard"
			} else {
				set := P.RuleSet{ID: p.RuleSetID, Name: p.Name, Type: "inline", Rules: rules, Revision: p.Generation + 1, Status: "enabled"}
				index := slices.IndexFunc(plan.state.Network.RuleSets, func(x P.RuleSet) bool { return x.ID == p.RuleSetID })
				kind := "Add"
				if index < 0 {
					plan.state.Network.RuleSets = append(plan.state.Network.RuleSets, set)
				} else {
					kind = "Update"
					old := plan.state.Network.RuleSets[index]
					if len(old.Rules) > 0 && len(rules)*100 < (100-p.MaxDeletePercent)*len(old.Rules) {
						plan.preview.Applicable = false
						plan.preview.Reason = "safety_guard"
					}
					plan.state.Network.RuleSets[index] = set
				}
				plan.preview.Entries = append(plan.preview.Entries, DiffEntry{Kind: kind, ID: p.RuleSetID, Change: "rules_snapshot"})
			}
		}
		p.Generation, e = p.Generation.Next()
		if e != nil {
			return ManagementPreview{}, e
		}
		plan.preview.Generation = p.Generation
		source.ETag = fetched.ETag
		source.LastModified = fetched.LastModified
		plan.sources[id] = source
	}
	p.Status = "healthy"
	p.LastSuccess = time.Now().UTC()
	p.LastError = ""
	p.Failures = 0
	plan.state.Management.Providers[pos] = p
	return s.saveManagementPlan(ctx, plan)
}
func (s *Service) recordProviderFailure(ctx context.Context, id identity.ID, code string, expected identity.Revision) {
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || ctx.Err() != nil {
		return
	}
	state, e := c.repo.ClientState(ctx)
	if e != nil || state.Revision != expected {
		return
	}
	pos := slices.IndexFunc(state.Management.Providers, func(p provider.Provider) bool { return p.ID == id })
	if pos < 0 {
		return
	}
	plan := newManagementPlan(state)
	p := &plan.state.Management.Providers[pos]
	p.LastError = code
	p.LastFailure = time.Now().UTC()
	p.Status = "degraded"
	p.Failures = min(p.Failures+1, 10)
	_, _ = s.commitManagement(ctx, plan, state)
}

// StartManagement starts a single timer coordinator and four workers after
// committed client recovery. Providers are staggered; startup does not fetch.
func (s *Service) StartManagement(ctx context.Context) error {
	if s.client == nil {
		return managementInvalid()
	}
	m := s.client.management
	m.schedulerMu.Lock()
	defer m.schedulerMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return identity.Err(identity.Unavailable, "provider management stopped")
	}
	if m.scheduleDone != nil {
		return nil
	}
	schedule, cancel := context.WithCancel(ctx)
	m.scheduleCancel = cancel
	m.scheduleDone = make(chan struct{})
	done := m.scheduleDone
	go s.managementScheduler(schedule, done)
	return nil
}
func scheduleDelay(p provider.Provider) time.Duration {
	delay := time.Duration(p.IntervalSeconds) * time.Second
	if p.Failures > 0 {
		backoff := min(time.Duration(1<<min(p.Failures, 10))*30*time.Second, 24*time.Hour)
		if backoff > delay {
			delay = backoff
		}
	}
	// Deterministic bounded jitter prevents startup storms without secret seeds.
	sum := 0
	for _, c := range p.ID {
		sum += int(c)
	}
	return delay + time.Duration(sum%31)*time.Second
}
func (s *Service) managementScheduler(ctx context.Context, done chan struct{}) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	s.runManagementScheduler(ctx, done, tick.C)
}
func (s *Service) runManagementScheduler(ctx context.Context, done chan struct{}, ticks <-chan time.Time) {
	defer close(done)
	jobs := make(chan identity.ID, 4)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case id := <-jobs:
					_, _ = s.RefreshProvider(ctx, id)
				}
			}
		}()
	}
	defer func() { workers.Wait() }()
	next := map[identity.ID]time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticks:
			c := s.client
			c.mu.Lock()
			state, e := c.repo.ClientState(ctx)
			closed := c.closed
			c.mu.Unlock()
			if e != nil || closed {
				continue
			}
			present := map[identity.ID]bool{}
			for _, p := range state.Management.Providers {
				present[p.ID] = true
				if !p.RefreshEnabled {
					delete(next, p.ID)
					continue
				}
				due, ok := next[p.ID]
				if !ok {
					next[p.ID] = now.Add(scheduleDelay(p))
					continue
				}
				if now.Before(due) {
					continue
				}
				select {
				case jobs <- p.ID:
					next[p.ID] = now.Add(scheduleDelay(p))
				default:
				}
			}
			for id := range next {
				if !present[id] {
					delete(next, id)
				}
			}
		}
	}
}
func (s *Service) StopManagementScheduler(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	m := s.client.management
	m.schedulerMu.Lock()
	defer m.schedulerMu.Unlock()
	m.mu.Lock()
	done, cancel := m.scheduleDone, m.scheduleCancel
	if cancel != nil {
		cancel()
	}
	m.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	if m.scheduleDone == done {
		m.scheduleDone = nil
		m.scheduleCancel = nil
	}
	m.mu.Unlock()
	return nil
}
func (s *Service) StopManagement(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	m := s.client.management
	m.mu.Lock()
	m.stopped = true
	m.cancel()
	m.notify()
	m.mu.Unlock()
	if e := s.StopManagementScheduler(ctx); e != nil {
		return e
	}
	for {
		m.mu.Lock()
		if m.active == 0 {
			m.mu.Unlock()
			break
		}
		changed := m.changed
		m.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.client.mu.Lock()
	clear(m.plans)
	s.client.mu.Unlock()
	return nil
}

type ProviderDiagnostics struct {
	LastError        string `json:"last_error,omitempty"`
	ProxyProviders   int    `json:"proxy_providers"`
	RuleSetProviders int    `json:"ruleset_providers"`
	Degraded         int    `json:"degraded"`
	StaleNodes       int    `json:"stale_nodes"`
	Scheduler        bool   `json:"scheduler"`
	ActiveRefreshes  int    `json:"active_refreshes"`
}

func (s *Service) ProviderDiagnostics(ctx context.Context) (ProviderDiagnostics, error) {
	var d ProviderDiagnostics
	if s.client == nil {
		return d, nil
	}
	c := s.client
	c.mu.Lock()
	state, e := c.repo.ClientState(ctx)
	c.mu.Unlock()
	if e != nil {
		return d, e
	}
	for _, p := range state.Management.Providers {
		if p.Kind == "proxy" {
			d.ProxyProviders++
		} else {
			d.RuleSetProviders++
		}
		if p.Status == "degraded" {
			d.Degraded++
		}
	}
	for _, n := range state.Nodes {
		if n.State == "stale" {
			d.StaleNodes++
		}
	}
	m := c.management
	m.mu.Lock()
	d.Scheduler = m.scheduleDone != nil
	d.ActiveRefreshes = m.active
	m.mu.Unlock()
	return d, nil
}
