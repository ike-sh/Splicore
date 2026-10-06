package application

import (
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func localActor() (identity.Actor, error) {
	id, e := identity.NewID()
	return identity.Actor{Principal: "local-control", RequestID: id}, e
}
func (s *Service) Inbounds(ctx context.Context) (InboundPage, error) {
	if s.runtime == nil {
		return InboundPage{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	return s.views(ctx)
}
func (s *Service) views(ctx context.Context) (InboundPage, error) {
	state, e := s.repo.State(ctx)
	if e != nil {
		return InboundPage{}, e
	}
	in, e := s.runtime.repo.Inbounds(ctx)
	if e != nil {
		return InboundPage{}, e
	}
	out := InboundPage{Items: []InboundView{}, Revision: state.Revision}
	underlayHealthy := s.underlay.Status().Health != "degraded"
	for _, i := range in {
		bs, e := s.bindings(ctx, i.ID)
		if e != nil {
			return InboundPage{}, e
		}
		v := InboundView{Inbound: i, Health: "stopped", Bindings: []BindingView{}}
		if len(bs) == 1 {
			v.BindingID = bs[0].ID
			v.AccountID = bs[0].AccountID
		}
		for _, b := range bs {
			bv := BindingView{BindingID: b.ID, AccountID: b.AccountID, Enabled: b.Enabled, Revision: b.Revision, PolicyID: b.PolicyOverrideID}
			if h, ok := s.runtime.handles[i.ID].(ports.AttributedStats); ok {
				bv.Stats = h.BindingStats(b.ID)
			}
			v.Bindings = append(v.Bindings, bv)
		}
		if h := s.runtime.handles[i.ID]; h != nil {
			v.Stats = h.Stats()
			if h.Health(ctx) == nil && underlayHealthy {
				v.Health = "healthy"
			} else {
				v.Health = "degraded"
			}
		}
		out.Items = append(out.Items, v)
	}
	return out, nil
}
func (s *Service) Inbound(ctx context.Context, id identity.ID) (InboundView, error) {
	if e := id.Validate(); e != nil {
		return InboundView{}, e
	}
	p, e := s.Inbounds(ctx)
	if e != nil {
		return InboundView{}, e
	}
	for _, v := range p.Items {
		if v.Inbound.ID == id {
			return v, nil
		}
	}
	return InboundView{}, identity.Err(identity.NotFound, "inbound not found")
}
func (s *Service) ExportSnell(ctx context.Context, id identity.ID, req ExportRequest) (ExportResult, error) {
	return s.ExportClient(ctx, id, req)
}
func (s *Service) ExportClient(ctx context.Context, id identity.ID, req ExportRequest) (ExportResult, error) {
	if s.runtime == nil {
		return ExportResult{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	page, e := s.views(ctx)
	if e != nil {
		return ExportResult{}, e
	}
	var i access.Inbound
	found := false
	for _, v := range page.Items {
		if v.Inbound.ID == id {
			i = v.Inbound
			found = true
		}
	}
	if !found {
		return ExportResult{}, identity.Err(identity.NotFound, "inbound not found")
	}
	bs, e := s.bindings(ctx, id)
	if e != nil {
		return ExportResult{}, e
	}
	var b access.Binding
	if req.BindingID == "" && len(bs) == 1 {
		b = bs[0]
	} else {
		if req.BindingID.Validate() != nil {
			return ExportResult{}, identity.Err(identity.Invalid, "explicit binding_id required for multi-user export")
		}
		for _, candidate := range bs {
			if candidate.ID == req.BindingID {
				b = candidate
			}
		}
	}
	if b.ID == "" {
		return ExportResult{}, identity.Err(identity.NotFound, "binding not found")
	}
	if !b.Enabled {
		return ExportResult{}, identity.Err(identity.Invalid, "binding disabled")
	}
	a, e := r.repo.Account(ctx, b.AccountID)
	if e != nil || !accountAllowed(a) {
		return ExportResult{}, identity.Err(identity.Invalid, "account unavailable for export")
	}
	c, e := r.repo.RevealCredential(ctx, b.CredentialID)
	if e != nil {
		return ExportResult{}, e
	}
	p, e := s.protocols.Get(i.Protocol)
	if e != nil {
		return ExportResult{}, e
	}
	authorized := ports.AuthorizedBinding{Inbound: i, Binding: b, Credential: c}
	if projection, ok := p.(ports.ClientServerCredentialProjection); ok && projection.ClientServerCredentials() {
		secrets, ok := r.repo.(ports.ServerSecretRepository)
		if !ok {
			return ExportResult{}, identity.Err(identity.Unavailable, "server identity credential unavailable")
		}
		authorized.ServerCredentials, e = secrets.RevealInboundCredentials(ctx, i.ID)
		if e != nil {
			return ExportResult{}, e
		}
	}
	profile, e := p.BuildClientProfile(ctx, authorized)
	if e != nil {
		return ExportResult{}, e
	}
	x, e := s.exporters.Get(req.Format)
	if e != nil {
		return ExportResult{}, e
	}
	content, e := x.Export(ctx, profile, ports.ExportTarget{Format: req.Format, ClientVersion: req.ClientVersion})
	if e != nil {
		return ExportResult{}, e
	}
	describer, ok := x.(ports.ExportDescriber)
	if !ok {
		return ExportResult{}, identity.Err(identity.UnsupportedExport, "export description unavailable")
	}
	d, e := describer.Describe(profile)
	if e != nil {
		return ExportResult{}, e
	}
	return ExportResult{Target: req.Format, ClientVersion: req.ClientVersion, ServerVersion: d.ServerVersion, ClientWireVersion: d.ClientWireVersion, Compatibility: d.Compatibility, Content: string(content), ContentShape: d.ContentShape}, nil
}
func (s *Service) SetDisplay(ctx context.Context, id identity.ID, req DisplayRequest) (identity.Transaction, error) {
	if s.runtime == nil {
		return identity.Transaction{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return identity.Transaction{}, identity.Err(identity.Unavailable, "runtime closed")
	}
	a, e := localActor()
	if e != nil {
		return identity.Transaction{}, e
	}
	inbounds, err := r.repo.Inbounds(ctx)
	if err != nil {
		return identity.Transaction{}, err
	}
	found := false
	for _, i := range inbounds {
		if i.ID == id {
			p, e := s.protocols.Get(i.Protocol)
			if e != nil || p.Metadata().Availability != ports.Compiled {
				return identity.Transaction{}, identity.Err(identity.NotImplemented, "display mutation unavailable")
			}
			found = true
			break
		}
	}
	if !found {
		return identity.Transaction{}, identity.Err(identity.NotFound, "inbound not found")
	}
	return r.repo.UpdateDisplay(ctx, id, req.Endpoint, req.ResourceRevision, req.Revision, a)
}

func safeOperation(err error) error {
	var de *identity.Error
	if errors.As(err, &de) {
		if de.Code == identity.Conflict {
			return identity.RevisionConflict(de.Current)
		}
		return identity.Err(de.Code, "runtime operation rejected")
	}
	return identity.Err(identity.Unavailable, "runtime operation failed")
}
