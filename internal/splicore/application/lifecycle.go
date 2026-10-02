package application

import (
	"context"
	"crypto/rand"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"sync"
	"time"
)

type runtimeState struct {
	mu      sync.Mutex
	repo    ports.RuntimeRepository
	handles map[identity.ID]ports.RuntimeHandle
	key     [32]byte
	closed  bool
}

func accountAllowed(a access.Account) bool {
	return a.Enabled && a.Status == access.Active && (a.ExpiresAt == nil || time.Now().Before(*a.ExpiresAt))
}
func (s *Service) EnableRuntime(ctx context.Context) error {
	r, ok := s.repo.(ports.RuntimeRepository)
	if !ok {
		return identity.Err(identity.Unavailable, "runtime repository unavailable")
	}
	state := &runtimeState{repo: r, handles: map[identity.ID]ports.RuntimeHandle{}}
	if _, e := rand.Read(state.key[:]); e != nil {
		return identity.Err(identity.Unavailable, "plan entropy unavailable")
	}
	s.runtime = state
	if e := r.RecoverPending(ctx); e != nil {
		return e
	}
	snapshot, e := r.State(ctx)
	if e != nil {
		return e
	}
	if snapshot.PendingTransactions > 0 {
		return identity.Err(identity.Unavailable, "unrecognized pending operation requires review")
	}
	inbounds, e := r.Inbounds(ctx)
	if e != nil {
		return e
	}
	for _, i := range inbounds {
		intent, e := s.projection(ctx, i, snapshot.Revision)
		if e != nil {
			s.CloseRuntime(context.Background())
			return e
		}
		h, e := s.prepare(ctx, intent)
		if e != nil {
			s.CloseRuntime(context.Background())
			return e
		}
		if e = h.Start(ctx); e == nil {
			e = h.Health(ctx)
		}
		if e != nil {
			_ = h.Close(context.Background())
			s.CloseRuntime(context.Background())
			return e
		}
		h.Activate()
		state.handles[i.ID] = h
	}
	return nil
}
func (s *Service) prepare(ctx context.Context, in ports.RuntimeIntent) (ports.RuntimeHandle, error) {
	p, e := s.protocols.Get(in.Inbound.Protocol)
	if e != nil {
		return nil, e
	}
	in, e = p.BuildRuntime(ctx, in)
	if e != nil {
		return nil, e
	}
	eng, e := s.engines.Get(in.Inbound.Engine)
	if e != nil {
		return nil, e
	}
	prepared, e := eng.Compile(ctx, in)
	if e != nil {
		return nil, e
	}
	h, ok := prepared.(ports.RuntimeHandle)
	if !ok {
		_ = prepared.Close(ctx)
		return nil, identity.Err(identity.Unavailable, "runtime lifecycle unavailable")
	}
	return h, nil
}
func (s *Service) CloseRuntime(ctx context.Context) error {
	clientErr := s.CloseClientRuntime(ctx)
	if s.runtime == nil {
		return clientErr
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	var err error = clientErr
	for id, h := range r.handles {
		if e := h.Close(ctx); e != nil {
			err = e
		}
		delete(r.handles, id)
	}
	return err
}
