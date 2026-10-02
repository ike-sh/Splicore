package clientruntime

import "context"

// WaitIdle observes session cleanup through notifications, without polling.
func (m *Manager) WaitIdle(ctx context.Context) error {
	for {
		m.mu.Lock()
		if len(m.sessions) == 0 {
			m.mu.Unlock()
			return nil
		}
		changed := m.changed
		m.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
