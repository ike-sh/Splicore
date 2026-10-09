package streamtransport

import (
	"context"
	"net"
	"os"
	"sync"
	"time"
)

// deadline changes wake existing waiters, including when a deadline is cleared.
type deadline struct {
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.at = t
	if d.changed != nil {
		close(d.changed)
	}
	d.changed = make(chan struct{})
}
func (d *deadline) snapshot() (time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changed == nil {
		d.changed = make(chan struct{})
	}
	return d.at, d.changed
}
func timer(t time.Time) (*time.Timer, <-chan time.Time) {
	if t.IsZero() {
		return nil, nil
	}
	v := time.NewTimer(time.Until(t))
	return v, v.C
}
func acquire(ctx context.Context, gate chan struct{}, d *deadline) error {
	for {
		t, changed := d.snapshot()
		if !t.IsZero() && !time.Now().Before(t) {
			return os.ErrDeadlineExceeded
		}
		tm, expired := timer(t)
		select {
		case <-ctx.Done():
			if tm != nil {
				tm.Stop()
			}
			return net.ErrClosed
		case <-changed:
			if tm != nil {
				tm.Stop()
			}
			continue
		case <-expired:
			return os.ErrDeadlineExceeded
		case <-gate:
			if tm != nil {
				tm.Stop()
			}
			return nil
		}
	}
}
