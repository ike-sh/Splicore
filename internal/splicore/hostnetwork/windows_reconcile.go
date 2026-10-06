package hostnetwork

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

// ReconcileWindowsBypass changes the desired set of an existing generation.
// It serializes only host control operations. New protection is fully installed
// before old protection is restored, and all intents precede their OS calls.
func (l *Lease) ReconcileWindowsBypass(ctx context.Context, plan WindowsBypassPlan) (err error) {
	if l == nil {
		return identity.Err(identity.Invalid, "missing bypass lease")
	}
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.lastError != "" || m.journal == nil {
		return identity.Err(identity.Unavailable, "bypass recovery required")
	}
	var g *Generation
	for i := range m.journal.Generations {
		if m.journal.Generations[i].ID == l.id {
			g = &m.journal.Generations[i]
			break
		}
	}
	if g == nil || g.State != "active" || m.journal.Scope != m.backend.Scope() {
		return identity.Err(identity.Conflict, "inactive bypass generation")
	}
	// Completed steps no longer own anything. Compact them before computing
	// indexes so repeated DNS changes cannot exhaust a live generation's journal.
	live := make([]Step, 0, len(g.Steps))
	for _, s := range g.Steps {
		if s.State != "restored" {
			live = append(live, s)
		}
	}
	g.Steps = live
	desired := map[string]Record{}
	for _, r := range plan.Records() {
		r.WindowsRoute.Generation = g.ID
		r.WindowsRoute.Owner = g.Owner
		if r.Validate() != nil || desired[r.key()].Kind != "" {
			return identity.Err(identity.Invalid, "invalid desired bypass set")
		}
		desired[r.key()] = r
	}
	existing := map[string]int{}
	for i, s := range g.Steps {
		if s.State != "restored" && s.Key.Kind == "windows-route" {
			current, e := m.backend.Read(ctx, s.Key)
			if e != nil || !equal(current, s.After) {
				g.Steps[i].State = "conflict"
				g.State = "conflict"
				m.lastError = "network_restore_conflict"
				return errors.Join(identity.Err(identity.Conflict, "active bypass protection changed"), e, m.persist())
			}
			existing[s.Key.key()] = i
		}
	}
	var added, removed []int
	var candidates []Step
	for _, raw := range plan.Records() {
		r := desired[raw.key()]
		if index, ok := existing[r.key()]; ok {
			if !sameWindowsRoute(g.Steps[index].After, &r) {
				return identity.Err(identity.Conflict, "bypass underlay changed; stop and replan")
			}
			continue
		}
		for _, other := range m.journal.Generations {
			if other.ID != g.ID && other.State != "restored" {
				for _, s := range other.Steps {
					if s.State != "restored" && s.Key.key() == r.key() {
						return identity.Err(identity.Conflict, "bypass route held by another generation")
					}
				}
			}
		}
		before, e := m.backend.Read(ctx, r)
		if e != nil {
			return e
		}
		if before != nil && !sameWindowsRoute(before, &r) {
			return identity.Err(identity.Conflict, "unrelated Windows route preserved")
		}
		candidates = append(candidates, Step{Key: r, Before: cloneRecord(before), After: cloneRecord(&r), State: "pending"})
	}
	if len(g.Steps)+len(candidates) > 512 {
		return identity.Err(identity.Unavailable, "bypass journal capacity exceeded")
	}
	for key, i := range existing {
		if _, ok := desired[key]; !ok {
			removed = append(removed, i)
		}
	}
	slices.Sort(removed)
	for _, s := range candidates {
		added = append(added, len(g.Steps))
		g.Steps = append(g.Steps, s)
	}
	if len(candidates) > 0 {
		m.journal.Schema = 2
	}
	if err = m.persist(); err != nil {
		return err
	}
	rollback := func(cause error) error {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var debt error
		for i := len(removed) - 1; i >= 0; i-- {
			s := &g.Steps[removed[i]]
			if s.State != "restored" || equal(s.Before, s.After) {
				continue
			}
			current, e := m.backend.Read(cleanup, s.Key)
			if e != nil || !equal(current, s.Before) {
				debt = errors.Join(debt, identity.Err(identity.Conflict, "bypass rollback current state changed"))
				continue
			}
			s.State = "pending"
			if e = m.persist(); e != nil {
				debt = errors.Join(debt, e)
				break
			}
			if b, ok := m.backend.(ownershipBackend); ok {
				if e = b.Authorize(*g); e != nil {
					debt = errors.Join(debt, e)
					break
				}
			}
			if e = m.backend.Write(cleanup, s.Key, s.After); e != nil {
				debt = errors.Join(debt, e)
				continue
			}
			current, e = m.backend.Read(cleanup, s.Key)
			if e != nil || !equal(current, s.After) {
				debt = errors.Join(debt, identity.Err(identity.Unavailable, "bypass rollback verification failed"))
				continue
			}
			s.State = "applied"
		}
		for i := len(added) - 1; i >= 0; i-- {
			debt = errors.Join(debt, m.restoreBypassStep(cleanup, g, &g.Steps[added[i]]))
		}
		// A preserved external edit is still a conflict, even when every newly
		// added route was successfully compensated. Do not admit another update.
		for _, s := range g.Steps {
			if s.State == "conflict" {
				debt = errors.Join(debt, identity.Err(identity.Conflict, "external bypass mutation preserved"))
			}
		}
		if debt != nil {
			g.State = "conflict"
			m.lastError = "network_restore_conflict"
		}
		return errors.Join(cause, debt, m.persist())
	}
	if b, ok := m.backend.(ownershipBackend); ok {
		if err = b.Authorize(*g); err != nil {
			return rollback(err)
		}
	}
	for _, index := range added {
		s := &g.Steps[index]
		current, e := m.backend.Read(ctx, s.Key)
		if e != nil || !equal(current, s.Before) {
			return rollback(identity.Err(identity.Conflict, "bypass state changed after snapshot"))
		}
		if !sameWindowsRoute(current, s.After) {
			if e = m.backend.Write(ctx, s.Key, s.After); e != nil {
				return rollback(e)
			}
		} else {
			s.Before = cloneRecord(s.After)
		}
		current, e = m.backend.Read(ctx, s.Key)
		if e != nil || !equal(current, s.After) {
			return rollback(identity.Err(identity.Unavailable, "bypass apply verification failed"))
		}
		s.State = "applied"
		if e = m.persist(); e != nil {
			return rollback(e)
		}
	}
	for _, index := range removed {
		if e := m.restoreBypassStep(ctx, g, &g.Steps[index]); e != nil {
			return rollback(e)
		}
	}
	// Metadata-only reference updates do not rewrite a kernel route. Borrowed
	// identical routes keep equal before/after snapshots and are never deleted.
	previous := map[int]Step{}
	for key, index := range existing {
		if r, ok := desired[key]; ok {
			s := &g.Steps[index]
			previous[index] = *s
			borrowed := equal(s.Before, s.After)
			s.Key = *cloneRecord(&r)
			s.After = cloneRecord(&r)
			if borrowed {
				s.Before = cloneRecord(&r)
			}
		}
	}
	if err = m.persist(); err != nil {
		for index, s := range previous {
			g.Steps[index] = s
		}
		return rollback(err)
	}
	return nil
}
func (m *Manager) restoreBypassStep(ctx context.Context, g *Generation, s *Step) error {
	if s.State == "restored" {
		return nil
	}
	current, e := m.backend.Read(ctx, s.Key)
	if e != nil {
		return e
	}
	if equal(current, s.Before) {
		s.State = "restored"
		return m.persist()
	}
	if !equal(current, s.After) {
		s.State = "conflict"
		return errors.Join(identity.Err(identity.Conflict, "external bypass mutation preserved"), m.persist())
	}
	if e = m.persist(); e != nil {
		return e
	}
	if b, ok := m.backend.(ownershipBackend); ok {
		if e = b.Authorize(*g); e != nil {
			return e
		}
	}
	if e = m.backend.Write(ctx, s.Key, s.Before); e != nil {
		return e
	}
	current, e = m.backend.Read(ctx, s.Key)
	if e != nil || !equal(current, s.Before) {
		return identity.Err(identity.Unavailable, "bypass restore verification failed")
	}
	s.State = "restored"
	return m.persist()
}
