package application

import (
	"context"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

// CheckCommitted validates the production projection without preparing or
// starting a runtime. The service is private to this offline validation call.
func (s *Service) CheckCommitted(ctx context.Context) error {
	repo, ok := s.repo.(ports.RuntimeRepository)
	if !ok {
		return identity.Err(identity.Unavailable, "runtime repository unavailable")
	}
	s.runtime = &runtimeState{repo: repo}
	defer func() { s.runtime = nil }()
	state, err := repo.State(ctx)
	if err != nil {
		return err
	}
	inbounds, err := repo.Inbounds(ctx)
	if err != nil {
		return err
	}
	for _, inbound := range inbounds {
		module, err := s.protocols.Get(inbound.Protocol)
		if err != nil {
			return err
		}
		if _, err := s.engines.Get(inbound.Engine); err != nil {
			return err
		}
		intent, err := s.projection(ctx, inbound, state.Revision)
		if err != nil {
			return err
		}
		if _, err = module.BuildRuntime(ctx, intent); err != nil {
			return err
		}
		if err = registry.CheckTLSResources(inbound.Settings.Data); err != nil {
			return err
		}
	}
	if clientRepo, ok := s.repo.(ports.ClientRepository); ok {
		clientState, err := clientRepo.ClientState(ctx)
		if err != nil {
			return err
		}
		return clientState.Validate()
	}
	return nil
}
