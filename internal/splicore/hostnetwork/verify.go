package hostnetwork

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

// Verify reads back every live resource of this journal generation. Borrowed
// identical resources are verified too, without acquiring deletion ownership.
func (l *Lease) Verify(ctx context.Context) error {
	if l == nil || l.manager == nil {
		return identity.Err(identity.Invalid, "missing host protection lease")
	}
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.journal == nil || m.lastError != "" || m.journal.Scope != m.backend.Scope() {
		return identity.Err(identity.Unavailable, "host protection requires recovery")
	}
	for _, g := range m.journal.Generations {
		if g.ID != l.id {
			continue
		}
		if g.State != "active" {
			return identity.Err(identity.Conflict, "inactive host protection")
		}
		for _, s := range g.Steps {
			if s.State == "restored" {
				continue
			}
			current, err := m.backend.Read(ctx, s.Key)
			if err != nil {
				return err
			}
			if !equal(current, s.After) {
				return identity.Err(identity.Conflict, "host protection changed")
			}
		}
		return nil
	}
	return identity.Err(identity.Conflict, "unknown host generation")
}
