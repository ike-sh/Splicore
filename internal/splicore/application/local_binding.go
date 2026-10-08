package application

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"time"
)

// Local bindings reuse the generic typed Account/Binding/Credential model. Their
// placement in existing local listener JSON avoids pretending a client listener
// is a managed remote server inbound solely to satisfy a legacy foreign key.
func (s *Service) mutateLocalBinding(ctx context.Context, out *clientCandidate, m ClientMutation, count int) error {
	inbound, index := -1, -1
	for j, i := range out.state.LocalInbounds {
		for k, b := range i.Bindings {
			if b.ID == m.ID {
				inbound, index = j, k
			}
		}
	}
	switch m.Action {
	case "create":
		if count != 1 || m.Binding == nil || m.Credential == nil || m.Binding.ID != "" || m.Binding.CredentialID != "" {
			return proxy.Invalid()
		}
		b := *m.Binding
		for j, i := range out.state.LocalInbounds {
			if i.ID == b.InboundID && i.Kind != "tun" {
				inbound = j
			}
		}
		if inbound < 0 {
			return proxy.Invalid()
		}
		a, e := s.client.repo.Account(ctx, b.AccountID)
		if e != nil || a.Validate() != nil {
			return proxy.Invalid()
		}
		b.ID, e = identity.NewID()
		if e != nil {
			return e
		}
		b.CredentialID, e = identity.NewID()
		if e != nil {
			return e
		}
		b.Stamp = identity.NewStamp(time.Now())
		c, e := localCredential(b, *m.Credential)
		if e != nil {
			return e
		}
		out.secrets = append(out.secrets, c)
		out.state.LocalInbounds[inbound].Bindings = append(out.state.LocalInbounds[inbound].Bindings, b)
		out.id = b.ID
	case "rotate":
		if inbound < 0 || count != 0 || m.Credential == nil {
			return proxy.Invalid()
		}
		b := &out.state.LocalInbounds[inbound].Bindings[index]
		id, e := identity.NewID()
		if e != nil {
			return e
		}
		b.CredentialID = id
		b.Revision++
		b.UpdatedAt = time.Now().UTC()
		c, e := localCredential(*b, *m.Credential)
		if e != nil {
			return e
		}
		out.secrets = append(out.secrets, c)
	case "update":
		if inbound < 0 || count != 1 || m.Binding == nil || m.Credential != nil {
			return proxy.Invalid()
		}
		old := out.state.LocalInbounds[inbound].Bindings[index]
		b := *m.Binding
		if b.ID != old.ID || b.AccountID != old.AccountID || b.InboundID != old.InboundID || b.CredentialID != old.CredentialID || b.PolicyOverrideID != nil {
			return proxy.Invalid()
		}
		old.Enabled = b.Enabled
		old.Revision++
		old.UpdatedAt = time.Now().UTC()
		out.state.LocalInbounds[inbound].Bindings[index] = old
	case "delete":
		if inbound < 0 || count != 0 || m.Credential != nil {
			return proxy.Invalid()
		}
		bs := out.state.LocalInbounds[inbound].Bindings
		out.state.LocalInbounds[inbound].Bindings = append(bs[:index], bs[index+1:]...)
	default:
		return proxy.Invalid()
	}
	return nil
}
func localCredential(b access.Binding, input CredentialInput) (access.Credential, error) {
	if input.Kind != access.UsernamePassword {
		return access.Credential{}, proxy.Invalid()
	}
	p, e := access.DecodeRemotePayload(input.Kind, input.Value)
	if e != nil {
		return access.Credential{}, e
	}
	id := b.AccountID
	c := access.Credential{ID: b.CredentialID, OwnerAccountID: &id, Kind: input.Kind, Schema: 1, State: "active", Payload: p, Stamp: identity.NewStamp(time.Now())}
	if c.Validate() != nil {
		return c, proxy.Invalid()
	}
	_, e = proxy.Pair(c)
	return c, e
}
