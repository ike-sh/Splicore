package application

import (
	"context"
	"slices"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
)

func (s *Service) addHTTPBinding(ctx context.Context, repo ports.MultiBindingRepository, in access.Inbound, bindings []access.Binding, req BindingRequest) (identity.Transaction, error) {
	if req.User == nil || req.BindingID != "" || req.Credential != nil || len(bindings) >= 16 {
		return identity.Transaction{}, identity.Err(identity.Invalid, "invalid HTTP proxy user enrollment")
	}
	if in.Revision != req.ResourceRevision {
		return identity.Transaction{}, identity.RevisionConflict(in.Revision)
	}
	module := proxy.HTTPInbound()
	user, err := module.UserDraft(*req.User)
	if err != nil {
		return identity.Transaction{}, err
	}
	payload, err := module.GenerateCreationCredential(user.Payload)
	if err != nil {
		return identity.Transaction{}, err
	}
	if err = uniqueProxyUsername(ctx, repo, bindings, "", payload.(access.UsernamePasswordPayload)); err != nil {
		return identity.Transaction{}, err
	}
	stamp := identity.NewStamp(time.Now())
	accountID, err := identity.NewID()
	if err != nil {
		return identity.Transaction{}, err
	}
	bindingID, err := identity.NewID()
	if err != nil {
		return identity.Transaction{}, err
	}
	credentialID, err := identity.NewID()
	if err != nil {
		return identity.Transaction{}, err
	}
	account := access.Account{ID: accountID, Name: user.Name, Status: access.Active, Enabled: user.AccountEnabled,
		ExpiresAt: user.ExpiresAt, Metadata: identity.Metadata{}, Stamp: stamp}
	binding := access.Binding{ID: bindingID, AccountID: accountID, InboundID: in.ID, CredentialID: credentialID,
		Enabled: user.Enabled, Stamp: stamp}
	credential := access.Credential{ID: credentialID, OwnerAccountID: &accountID, Kind: payload.Kind(), Schema: 1,
		State: "active", Payload: payload, Stamp: stamp}
	old, err := s.projection(ctx, in, req.Revision)
	if err != nil {
		return identity.Transaction{}, err
	}
	candidate := old
	if binding.Enabled && accountAllowed(account) {
		candidate.Bindings = append(slices.Clone(old.Bindings), binding)
		candidate.Credentials = append(slices.Clone(old.Credentials), credential)
	}
	return s.replaceBindingRuntime(ctx, repo, module, old, candidate, func(w ports.Writer) error {
		if err := w.CreateAccount(account); err != nil {
			return err
		}
		if err := w.CreateCredential(credential); err != nil {
			return err
		}
		return w.CreateBinding(binding)
	})
}
