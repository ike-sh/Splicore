// Package hostnetwork owns reversible platform mutations, never desired configuration.
package hostnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
)

const MaxJournalBytes = 2 << 20

// Records are private operational state. Public diagnostics expose only summaries.
type Record struct {
	Kind         string                  `json:"kind"`
	Interface    string                  `json:"interface,omitempty"`
	Index        int                     `json:"index,omitempty"`
	Addresses    []string                `json:"addresses,omitempty"`
	MTU          uint32                  `json:"mtu,omitempty"`
	Prefix       string                  `json:"prefix,omitempty"`
	Gateway      string                  `json:"gateway,omitempty"`
	Table        int                     `json:"table,omitempty"`
	Priority     int                     `json:"priority,omitempty"`
	Family       int                     `json:"family,omitempty"`
	Protocol     int                     `json:"protocol,omitempty"`
	Metric       int                     `json:"metric,omitempty"`
	Throw        bool                    `json:"throw,omitempty"`
	UID          *uint32                 `json:"uid,omitempty"`
	Mark         uint32                  `json:"mark,omitempty"`
	Invert       bool                    `json:"invert,omitempty"`
	Proxy        *ProxyState             `json:"proxy,omitempty"`
	WinINET      *WinINETSnapshot        `json:"wininet,omitempty"`
	Adapter      *WindowsAdapterIdentity `json:"adapter,omitempty"`
	WindowsRoute *WindowsRouteState      `json:"windows_route,omitempty"`
}
type ProxyValue struct {
	Present bool   `json:"present"`
	Type    uint32 `json:"type"`
	Number  uint32 `json:"number,omitempty"`
	Text    string `json:"text,omitempty"`
}
type ProxyState struct {
	Values map[string]ProxyValue `json:"values"`
}

func (r Record) Validate() error {
	bad := func() error { return identity.Err(identity.Corrupt, "invalid operational network record") }
	shape := r
	shape.Kind = ""
	switch r.Kind {
	case "interface":
		shape.Adapter = nil
		shape.Interface = ""
		shape.Index = 0
		shape.Addresses = nil
		shape.MTU = 0
	case "address":
		shape.Adapter = nil
		shape.Interface = ""
		shape.Index = 0
		shape.Prefix = ""
	case "route":
		shape.Interface = ""
		shape.Index = 0
		shape.Prefix = ""
		shape.Gateway = ""
		shape.Table = 0
		shape.Protocol = 0
		shape.Metric = 0
		shape.Throw = false
	case "rule":
		shape.Priority = 0
		shape.Table = 0
		shape.Family = 0
		shape.UID = nil
		shape.Mark = 0
		shape.Invert = false
	case "proxy":
		shape.Proxy = nil
	case "wininet":
		shape.WinINET = nil
	case "session":
		shape.Interface = ""
		shape.Adapter = nil
	case "windows-route":
		shape.WindowsRoute = nil
	}
	if !reflect.DeepEqual(shape, Record{}) {
		return bad()
	}
	if r.Interface != "" && (!identity.Label(r.Interface, 15) || strings.ContainsAny(r.Interface, "/\\ :")) {
		return bad()
	}
	if r.Index < 0 || r.Table < 0 || r.Table > 1<<30 || r.Priority < 0 || r.Priority > 32765 || r.Metric < 0 || r.Metric > 1<<30 {
		return bad()
	}
	if r.Adapter != nil && r.Adapter.Validate() != nil {
		return bad()
	}
	switch r.Kind {
	case "interface":
		if r.Interface == "" || r.MTU < 1280 || r.MTU > 9000 || len(r.Addresses) < 1 || len(r.Addresses) > 2 || r.Proxy != nil {
			return bad()
		}
		for _, p := range r.Addresses {
			if _, err := netip.ParsePrefix(p); err != nil {
				return bad()
			}
		}
	case "address":
		if r.Interface == "" || r.Proxy != nil {
			return bad()
		}
		if _, err := netip.ParsePrefix(r.Prefix); err != nil {
			return bad()
		}
	case "route":
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil || p.Masked().String() != r.Prefix || r.Protocol != 198 || r.Proxy != nil {
			return bad()
		}
		if !r.Throw && r.Interface == "" {
			return bad()
		}
		if r.Gateway != "" {
			ip, e := netip.ParseAddr(r.Gateway)
			if e != nil || ip.Is4() != p.Addr().Is4() {
				return bad()
			}
		}
	case "rule":
		if r.Priority < 1 || r.Table < 1 || r.Family != 4 && r.Family != 6 || r.Proxy != nil {
			return bad()
		}
	case "proxy":
		if r.Interface != "" || r.Proxy == nil || len(r.Proxy.Values) != 1 {
			return bad()
		}
		for key, v := range r.Proxy.Values {
			if key != "ProxyEnable" && key != "ProxyServer" && key != "ProxyOverride" && key != "AutoConfigURL" && key != "AutoDetect" {
				return bad()
			}
			if v.Type != 0 && v.Type != 1 && v.Type != 4 || len(v.Text) > 4096 || strings.ContainsAny(v.Text, "@\r\n\x00") {
				return bad()
			}
			if !v.Present && (v.Type != 0 || v.Number != 0 || v.Text != "") || v.Present && v.Type == 0 || v.Type == 1 && v.Number != 0 || v.Type == 4 && v.Text != "" {
				return bad()
			}
			if key == "AutoConfigURL" && v.Text != "" {
				u, e := url.Parse(v.Text)
				if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
					return bad()
				}
			}
		}
	case "wininet":
		if r.WinINET == nil || r.WinINET.Validate() != nil {
			return bad()
		}
	case "session":
		if r.Interface == "" || r.Adapter == nil {
			return bad()
		}
	case "windows-route":
		if r.WindowsRoute == nil || r.WindowsRoute.Validate() != nil {
			return bad()
		}
	default:
		return bad()
	}
	return nil
}
func (r Record) key() string {
	switch r.Kind {
	case "interface":
		return "interface:" + r.Interface
	case "address":
		return "address:" + r.Interface + ":" + r.Prefix
	case "route":
		return fmt.Sprintf("route:%d:%s", r.Table, r.Prefix)
	case "rule":
		return fmt.Sprintf("rule:%d:%d", r.Family, r.Priority)
	case "windows-route":
		return "windows-route:" + r.WindowsRoute.Destination
	default:
		if r.Kind == "proxy" {
			for key := range r.Proxy.Values {
				return "proxy:" + key
			}
		}
		return r.Kind
	}
}

type Backend interface {
	Scope() string
	Read(context.Context, Record) (*Record, error)
	Write(context.Context, Record, *Record) error
}
type ownershipBackend interface {
	OwnershipRecords(identity.ID, identity.ID, []Record) ([]Record, error)
	Authorize(Generation) error
}
type JournalStore interface {
	Load() (*Journal, error)
	Save(*Journal) error
	Close() error
}
type Step struct {
	Key               Record    `json:"key"`
	Before            *Record   `json:"before,omitempty"`
	After             *Record   `json:"after,omitempty"`
	State             string    `json:"state"`
	Intermediates     []*Record `json:"intermediates,omitempty"`
	BeforeFingerprint string    `json:"before_fingerprint,omitempty"`
}
type Generation struct {
	ID        identity.ID `json:"id"`
	Owner     identity.ID `json:"owner"`
	Timestamp time.Time   `json:"timestamp"`
	State     string      `json:"state"`
	Steps     []Step      `json:"steps"`
}
type Journal struct {
	Schema      int          `json:"schema"`
	Platform    string       `json:"platform"`
	Scope       string       `json:"scope"`
	Generations []Generation `json:"generations"`
}

func DecodeJournal(b []byte) (*Journal, error) {
	var j Journal
	if jsonstrict.DecodeLimit(b, &j, MaxJournalBytes) != nil || (j.Schema != 1 && j.Schema != 2) || j.Platform != "linux" && j.Platform != "windows" || !identity.Label(j.Scope, 512) || len(j.Generations) > 32 {
		return nil, identity.Err(identity.Corrupt, "network recovery journal is invalid")
	}
	seen := map[identity.ID]bool{}
	for _, g := range j.Generations {
		if g.ID.Validate() != nil || g.Owner.Validate() != nil || seen[g.ID] || g.Timestamp.IsZero() || len(g.Steps) > 512 || !validState(g.State) {
			return nil, identity.Err(identity.Corrupt, "network recovery generation is invalid")
		}
		seen[g.ID] = true
		keys := map[string]bool{}
		for _, s := range g.Steps {
			if j.Schema == 1 && (s.Key.Kind == "session" || s.Key.Adapter != nil || s.Key.Kind == "windows-route") {
				return nil, identity.Err(identity.Corrupt, "new ownership record in old journal")
			}
			if s.Key.Validate() != nil || keys[s.Key.key()] || !validState(s.State) {
				return nil, identity.Err(identity.Corrupt, "network recovery step is invalid")
			}
			keys[s.Key.key()] = true
			if s.Key.Adapter != nil && (s.Key.Adapter.Generation != g.ID || s.Key.Adapter.Owner != g.Owner) {
				return nil, identity.Err(identity.Corrupt, "adapter journal generation mismatch")
			}
			if s.Key.WindowsRoute != nil && (s.Key.WindowsRoute.Generation != g.ID || s.Key.WindowsRoute.Owner != g.Owner) {
				return nil, identity.Err(identity.Corrupt, "Windows route journal generation mismatch")
			}
			if len(s.Intermediates) > 64 || (len(s.Intermediates) > 0 && s.Key.Kind != "wininet") || (j.Schema == 1 && (s.Key.Kind == "wininet" || len(s.Intermediates) > 0 || s.BeforeFingerprint != "")) {
				return nil, identity.Err(identity.Corrupt, "invalid recovery transitions")
			}
			if s.Key.Kind == "wininet" && (s.Before == nil || s.Before.WinINET == nil || s.BeforeFingerprint != s.Before.WinINET.Fingerprint()) {
				return nil, identity.Err(identity.Corrupt, "invalid WinINET recovery fingerprint")
			}
			for _, r := range s.Intermediates {
				if r == nil || r.Validate() != nil || r.key() != s.Key.key() {
					return nil, identity.Err(identity.Corrupt, "invalid recovery transition")
				}
			}
			for _, r := range []*Record{s.Before, s.After} {
				if r != nil && (r.Validate() != nil || r.key() != s.Key.key()) {
					return nil, identity.Err(identity.Corrupt, "network recovery state is invalid")
				}
				if r != nil && s.Key.Adapter != nil && (r.Adapter == nil || *r.Adapter != *s.Key.Adapter) {
					return nil, identity.Err(identity.Corrupt, "adapter recovery identity changed")
				}
				if r != nil && s.Key.WindowsRoute != nil && !sameWindowsRoute(r, &s.Key) {
					return nil, identity.Err(identity.Corrupt, "route recovery identity changed")
				}
			}
		}
	}
	return &j, nil
}
func validState(s string) bool {
	return s == "pending" || s == "applied" || s == "active" || s == "restored" || s == "conflict"
}

type Status struct {
	Platform          string `json:"platform"`
	Recovery          string `json:"recovery"`
	ActiveGenerations int    `json:"active_generations"`
	OwnedRoutes       int    `json:"owned_routes"`
	OwnedInterfaces   int    `json:"owned_interfaces"`
	SystemProxy       bool   `json:"system_proxy_owned"`
	LastError         string `json:"last_error,omitempty"`
}
type Manager struct {
	mu            sync.Mutex // serializes control operations; never a payload data path lock
	backend       Backend
	store         JournalStore
	journal       *Journal
	owner         identity.ID
	lastError     string
	closed        bool
	backendClosed bool
	storeClosed   bool
}
type Lease struct {
	manager *Manager
	id      identity.ID
}

func New(backend Backend, store JournalStore) (*Manager, error) {
	if backend.Scope() == "" {
		return nil, identity.Err(identity.Unavailable, "host network ownership scope unavailable")
	}
	owner, err := identity.NewID()
	if err != nil {
		return nil, err
	}
	m := &Manager{backend: backend, store: store, owner: owner}
	m.journal, err = store.Load()
	if err != nil {
		m.lastError = "journal_corrupt"
		return m, err
	}
	if m.journal == nil {
		m.journal = &Journal{Schema: 1, Platform: runtime.GOOS, Scope: backend.Scope(), Generations: []Generation{}}
	}
	return m, nil
}
func cloneRecord(r *Record) *Record {
	if r == nil {
		return nil
	}
	b, _ := json.Marshal(r)
	var out Record
	_ = json.Unmarshal(b, &out)
	return &out
}
func equal(a, b *Record) bool { return reflect.DeepEqual(a, b) }
func (m *Manager) persist() error {
	if err := m.store.Save(m.journal); err != nil {
		m.lastError = "journal_write_failed"
		return identity.Err(identity.Unavailable, "network journal write failed")
	}
	return nil
}

// Prepare persists every prior state before the first host write. Ready starts the
// data plane after interface/address setup and before capture routes or proxy.
func (m *Manager) Prepare(ctx context.Context, desired []Record, ready func() error, stopBeforeRestore ...func()) (lease *Lease, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.lastError != "" || m.journal == nil {
		return nil, identity.Err(identity.Unavailable, "host network recovery required")
	}
	if len(desired) < 1 || len(desired) > 512 {
		return nil, identity.Err(identity.Invalid, "invalid network mutation plan")
	}
	id, e := identity.NewID()
	if e != nil {
		return nil, e
	}
	g := Generation{ID: id, Owner: m.owner, Timestamp: time.Now().UTC(), State: "pending", Steps: []Step{}}
	if b, ok := m.backend.(ownershipBackend); ok {
		desired, e = b.OwnershipRecords(id, m.owner, desired)
		if e != nil {
			return nil, e
		}
	}
	keys := map[string]bool{}
	for _, r := range desired {
		if r.Validate() != nil || keys[r.key()] {
			return nil, identity.Err(identity.Invalid, "invalid network mutation plan")
		}
		keys[r.key()] = true
		for _, existing := range m.journal.Generations {
			if existing.State != "restored" {
				for _, s := range existing.Steps {
					if s.State != "restored" && s.Key.key() == r.key() {
						return nil, identity.Err(identity.Conflict, "host network resource already owned")
					}
				}
			}
		}
		before, e := m.backend.Read(ctx, r)
		if e != nil {
			return nil, identity.Err(identity.Unavailable, "host network snapshot failed")
		}
		if before != nil && r.Kind != "proxy" && r.Kind != "wininet" && !(r.Kind == "windows-route" && sameWindowsRoute(before, &r)) {
			return nil, identity.Err(identity.Conflict, "host network resource collision")
		}
		if before != nil && before.Validate() != nil {
			return nil, identity.Err(identity.Invalid, "previous system proxy contains unsupported or sensitive state")
		}
		step := Step{Key: r, Before: cloneRecord(before), After: cloneRecord(&r), State: "pending"}
		if r.Kind == "wininet" {
			if before == nil || before.WinINET == nil {
				return nil, identity.Err(identity.Unavailable, "WinINET snapshot missing")
			}
			b, ok := m.backend.(TransitionBackend)
			if !ok {
				return nil, identity.Err(identity.NotImplemented, "WinINET transition ownership unavailable")
			}
			step.Intermediates, e = b.Transitions(r, before, &r)
			if e != nil {
				return nil, e
			}
			step.BeforeFingerprint = before.WinINET.Fingerprint()
			m.journal.Schema = 2
		}
		g.Steps = append(g.Steps, step)
		if r.Adapter != nil || r.Kind == "session" || r.Kind == "windows-route" {
			m.journal.Schema = 2
		}
	}
	for len(m.journal.Generations) >= 32 {
		if m.journal.Generations[0].State != "restored" {
			return nil, identity.Err(identity.Unavailable, "network journal capacity exceeded")
		}
		m.journal.Generations = m.journal.Generations[1:]
	}
	m.journal.Generations = append(m.journal.Generations, g)
	index := len(m.journal.Generations) - 1
	if err = m.persist(); err != nil {
		m.journal.Generations = m.journal.Generations[:index]
		return nil, err
	}
	lease = &Lease{m, id}
	started := false
	defer func() {
		if err != nil {
			if started {
				for _, stop := range stopBeforeRestore {
					if stop != nil {
						stop()
					}
				}
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			restoreErr := m.restore(cleanup, index, false)
			err = errors.Join(err, restoreErr)
		}
	}()
	if b, ok := m.backend.(ownershipBackend); ok {
		if err = b.Authorize(g); err != nil {
			return lease, err
		}
	}
	for i := range m.journal.Generations[index].Steps {
		s := &m.journal.Generations[index].Steps[i]
		if !started && s.Key.Kind != "interface" && s.Key.Kind != "address" && s.Key.Kind != "session" {
			started = true
			if ready != nil {
				if err = ready(); err != nil {
					return lease, err
				}
			}
		}
		current, e := m.backend.Read(ctx, s.Key)
		if e != nil || !equal(current, s.Before) {
			err = identity.Err(identity.Conflict, "network state changed after snapshot")
			return lease, err
		}
		if s.Key.Kind == "windows-route" && sameWindowsRoute(current, s.After) {
			s.Before = cloneRecord(s.After)
			s.State = "applied"
			if err = m.persist(); err != nil {
				return lease, err
			}
			continue
		}
		if err = m.backend.Write(ctx, s.Key, s.After); err != nil {
			return lease, identity.Err(identity.Unavailable, "host network apply failed")
		}
		actual, e := m.backend.Read(ctx, s.Key)
		if e == nil && actual != nil && s.After.Index == 0 && actual.Index > 0 {
			s.After.Index = actual.Index
		}
		if e != nil || !equal(actual, s.After) {
			err = identity.Err(identity.Unavailable, "host network verification failed")
			return lease, err
		}
		s.State = "applied"
		if err = m.persist(); err != nil {
			return lease, err
		}
	}
	if !started && ready != nil {
		started = true
		if err = ready(); err != nil {
			return lease, err
		}
	}
	m.journal.Generations[index].State = "active"
	err = m.persist()
	return lease, err
}
func (m *Manager) restore(ctx context.Context, index int, recovery bool) error {
	g := &m.journal.Generations[index]
	var all error
	for i := len(g.Steps) - 1; i >= 0; i-- {
		s := &g.Steps[i]
		if s.State == "restored" {
			continue
		}
		if s.Key.Kind == "interface" && s.Key.Adapter != nil && all != nil {
			// Removing the parent adapter also removes its child addresses/routes.
			// Keep that exact parent debt while any earlier compensation failed.
			all = errors.Join(all, identity.Err(identity.Conflict, "Wintun child recovery must complete before adapter removal"))
			continue
		}
		current, e := m.backend.Read(ctx, s.Key)
		if e != nil {
			all = errors.Join(all, identity.Err(identity.Unavailable, "network restore snapshot failed"))
			continue
		}
		if equal(current, s.Before) {
			if b, ok := m.backend.(TransitionBackend); ok && s.Key.Kind == "wininet" {
				if m.journal.Scope != m.backend.Scope() || m.journal.Platform != runtime.GOOS {
					all = errors.Join(all, identity.Err(identity.Conflict, "foreign WinINET recovery scope"))
					continue
				}
				if e = m.persist(); e != nil {
					all = errors.Join(all, e)
					break
				}
				if b, ok := m.backend.(ownershipBackend); ok {
					if e = b.Authorize(*g); e != nil {
						all = errors.Join(all, e)
						break
					}
				}
				if e = b.FinalizeRestore(ctx, s.Key); e != nil {
					all = errors.Join(all, e)
					continue
				}
			}
			s.State = "restored"
			continue
		}
		if m.journal.Scope != m.backend.Scope() || m.journal.Platform != runtime.GOOS || recovery && s.Key.Kind == "interface" && s.After != nil && s.After.Index == 0 && s.After.Adapter == nil || !knownTransition(current, *s) {
			s.State = "conflict"
			all = errors.Join(all, identity.Err(identity.Conflict, "external network mutation preserved"))
			continue
		}
		if b, ok := m.backend.(TransitionBackend); ok && s.Key.Kind == "wininet" {
			transitions, err := b.Transitions(s.Key, current, s.Before)
			if err != nil {
				all = errors.Join(all, err)
				continue
			}
			for _, r := range transitions {
				found := false
				for _, v := range s.Intermediates {
					if equal(r, v) {
						found = true
						break
					}
				}
				if !found {
					s.Intermediates = append(s.Intermediates, r)
				}
			}
			if len(s.Intermediates) > 64 {
				all = errors.Join(all, identity.Err(identity.Unavailable, "recovery transition capacity exceeded"))
				continue
			}
		}
		// Persist restore intent before its write; a crash can compare both states.
		if e = m.persist(); e != nil {
			all = errors.Join(all, e)
			break
		}
		if b, ok := m.backend.(ownershipBackend); ok {
			if e = b.Authorize(*g); e != nil {
				all = errors.Join(all, e)
				break
			}
		}
		writeKey := s.Key
		if s.After != nil {
			writeKey = *s.After
		}
		if e = m.backend.Write(ctx, writeKey, s.Before); e != nil {
			all = errors.Join(all, identity.Err(identity.Unavailable, "network restore failed"))
			continue
		}
		actual, e := m.backend.Read(ctx, s.Key)
		if e != nil || !equal(actual, s.Before) {
			all = errors.Join(all, identity.Err(identity.Unavailable, "network restore verification failed"))
			continue
		}
		s.State = "restored"
	}
	if all == nil {
		g.State = "restored"
	} else {
		g.State = "conflict"
		m.lastError = "network_restore_conflict"
	}
	return errors.Join(all, m.persist())
}
func (l *Lease) Restore(ctx context.Context) error {
	if l == nil {
		return nil
	}
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.journal.Generations {
		if m.journal.Generations[i].ID == l.id {
			return m.restore(ctx, i, false)
		}
	}
	return identity.Err(identity.Corrupt, "network generation missing")
}
func (m *Manager) Recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.journal == nil {
		return identity.Err(identity.Corrupt, "network journal is corrupt")
	}
	var err error
	for i := len(m.journal.Generations) - 1; i >= 0; i-- {
		if m.journal.Generations[i].State != "restored" {
			err = errors.Join(err, m.restore(ctx, i, true))
		}
	}
	if err == nil {
		m.lastError = ""
		m.journal.Scope = m.backend.Scope()
		m.journal.Platform = runtime.GOOS
		err = m.persist()
	}
	return err
}
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{Platform: runtime.GOOS, Recovery: "clean", LastError: m.lastError}
	if m.lastError != "" {
		s.Recovery = "degraded"
	}
	if m.journal == nil {
		return s
	}
	for _, g := range m.journal.Generations {
		if g.State == "restored" {
			continue
		}
		s.ActiveGenerations++
		for _, step := range g.Steps {
			if step.State == "restored" {
				continue
			}
			switch step.Key.Kind {
			case "route", "windows-route":
				if !equal(step.Before, step.After) {
					s.OwnedRoutes++
				}
			case "interface":
				s.OwnedInterfaces++
			case "proxy", "wininet":
				s.SystemProxy = true
			}
		}
	}
	return s
}
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed && m.backendClosed && m.storeClosed {
		return nil
	}
	m.closed = true
	var err error
	if !m.backendClosed {
		if backend, ok := m.backend.(interface{ Close() error }); ok {
			err = backend.Close()
		}
		m.backendClosed = err == nil
	}
	if !m.storeClosed {
		e := m.store.Close()
		m.storeClosed = e == nil
		err = errors.Join(err, e)
	}
	return err
}

func (m *Manager) SystemProxyPlan(endpoint string) ([]Record, error) {
	if b, ok := m.backend.(interface {
		SystemProxyPlan(string) ([]Record, error)
	}); ok {
		return b.SystemProxyPlan(endpoint)
	}
	return ProxyPlan(endpoint), nil
}
