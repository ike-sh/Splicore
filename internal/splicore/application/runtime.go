package application

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"time"
)

type BindingView struct {
	BindingID      identity.ID       `json:"binding_id"`
	AccountID      identity.ID       `json:"account_id"`
	Enabled        bool              `json:"enabled"`
	Revision       identity.Revision `json:"revision"`
	PolicyID       *identity.ID      `json:"traffic_policy_id,omitempty"`
	PolicyEnforced bool              `json:"policy_enforced"`
	Stats          ports.Stats       `json:"stats"`
}

func (s *Service) bindings(ctx context.Context, id identity.ID) ([]access.Binding, error) {
	if repo, ok := s.runtime.repo.(ports.MultiBindingRepository); ok {
		return repo.Bindings(ctx, id)
	}
	b, err := s.runtime.repo.Binding(ctx, id)
	if err != nil {
		return nil, err
	}
	return []access.Binding{b}, nil
}
func (s *Service) projection(ctx context.Context, i access.Inbound, revision identity.Revision) (ports.RuntimeIntent, error) {
	in := ports.RuntimeIntent{Inbound: i, Revision: revision}
	bs, err := s.bindings(ctx, i.ID)
	if err != nil {
		return in, err
	}
	if len(bs) == 0 || len(bs) > 16 {
		return in, identity.Err(identity.Corrupt, "invalid inbound bindings")
	}
	for _, b := range bs {
		a, err := s.repo.Account(ctx, b.AccountID)
		if err != nil {
			return in, err
		}
		if !b.Enabled || !accountAllowed(a) {
			continue
		}
		c, err := s.runtime.repo.RevealCredential(ctx, b.CredentialID)
		if err != nil {
			return in, err
		}
		in.Bindings = append(in.Bindings, b)
		in.Credentials = append(in.Credentials, c)
	}
	return in, nil
}

// commitCandidate owns the common pending/start/health/commit/admission sequence.
func (s *Service) commitCandidate(ctx context.Context, intent ports.RuntimeIntent, begin func(context.Context, identity.Revision, identity.Actor) (identity.Transaction, error), write func(ports.Writer) error) (op identity.Transaction, err error) {
	actor, err := localActor()
	if err != nil {
		return op, err
	}
	op, err = begin(ctx, intent.Revision, actor)
	if err != nil {
		return op, err
	}
	committed := false
	var h ports.RuntimeHandle
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if h != nil {
				_ = h.Close(cleanup)
			}
			_ = s.runtime.repo.FailOperation(cleanup, op)
		}
	}()
	h, err = s.prepare(ctx, intent)
	if err != nil {
		return op, err
	}
	if err = h.Start(ctx); err == nil {
		err = h.Health(ctx)
	}
	if err != nil {
		return op, err
	}
	if err = s.runtime.repo.CommitOperation(ctx, op, write); err != nil {
		return op, safeOperation(err)
	}
	committed = true
	h.Activate()
	s.runtime.handles[intent.Inbound.ID] = h
	_ = op.Finish(identity.Committed, time.Now(), "")
	return op, nil
}
