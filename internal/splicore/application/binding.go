package application

import (
	"context"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"time"
)

type BindingRequest struct {
	Action           string            `json:"action,omitempty"`
	Credential       *CredentialInput  `json:"credential,omitempty"`
	BindingID        identity.ID       `json:"binding_id"`
	Enabled          bool              `json:"enabled"`
	ResourceRevision identity.Revision `json:"resource_revision"`
	Revision         identity.Revision `json:"revision"`
}

func (BindingRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("BindingRequest{[REDACTED]}"))
}

// SetBinding replaces only its owned Inbound. Rollback restores committed credentials.
func (s *Service) SetBinding(ctx context.Context, id identity.ID, req BindingRequest) (op identity.Transaction, err error) {
	if s.runtime == nil {
		return op, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return op, identity.Err(identity.Unavailable, "runtime closed")
	}
	if id.Validate() != nil || req.BindingID.Validate() != nil {
		return op, identity.Err(identity.Invalid, "invalid binding request")
	}
	repo, ok := r.repo.(ports.MultiBindingRepository)
	if !ok {
		return op, identity.Err(identity.NotImplemented, "binding mutation unavailable")
	}
	state, err := repo.State(ctx)
	if err != nil {
		return op, err
	}
	if state.Revision != req.Revision {
		return op, identity.RevisionConflict(state.Revision)
	}
	all, err := repo.Inbounds(ctx)
	if err != nil {
		return op, err
	}
	var i access.Inbound
	for _, v := range all {
		if v.ID == id {
			i = v
		}
	}
	p, err := s.protocols.Get(i.Protocol)
	engine, engineErr := s.engines.Get(i.Engine)
	if err != nil || engineErr != nil || ports.EffectiveCapabilities(p.Capabilities(ports.CapabilityContext{Engine: i.Engine}), engine.Capabilities()).Mutation.Users != ports.Restart {
		return op, identity.Err(identity.NotImplemented, "binding mutation unsupported")
	}
	bs, err := repo.Bindings(ctx, id)
	if err != nil {
		return op, err
	}
	var target *access.Binding
	for n := range bs {
		if bs[n].ID == req.BindingID {
			target = &bs[n]
		}
	}
	if target == nil {
		return op, identity.Err(identity.NotFound, "binding not found")
	}
	if target.Revision != req.ResourceRevision {
		return op, identity.RevisionConflict(target.Revision)
	}
	if req.Action != "" && req.Action != "rotate" && req.Action != "delete" || (req.Action == "rotate") != (req.Credential != nil) {
		return op, identity.Err(identity.Invalid, "invalid binding mutation")
	}
	var rotated access.Credential
	if req.Action == "rotate" {
		rotated, err = repo.RevealCredential(ctx, target.CredentialID)
		if err != nil {
			return op, err
		}
		payload, e := access.DecodeRemotePayload(req.Credential.Kind, req.Credential.Value)
		if e != nil || req.Credential.Kind != rotated.Kind {
			return op, identity.Err(identity.Invalid, "invalid credential rotation")
		}
		rotated.Payload = payload
		if p.ValidateCredential(rotated) != nil {
			return op, identity.Err(identity.Invalid, "invalid credential rotation")
		}
	}
	oldIntent, err := s.projection(ctx, i, state.Revision)
	if err != nil {
		return op, err
	}
	if req.Action == "" {
		target.Enabled = req.Enabled
	}
	candidate := ports.RuntimeIntent{Inbound: i, Revision: state.Revision, ServerCredentials: oldIntent.ServerCredentials}
	for _, b := range bs {
		if req.Action == "delete" && b.ID == target.ID {
			continue
		}
		a, err := repo.Account(ctx, b.AccountID)
		if err != nil {
			return op, err
		}
		if !b.Enabled || !accountAllowed(a) {
			continue
		}
		c, err := repo.RevealCredential(ctx, b.CredentialID)
		if err != nil {
			return op, err
		}
		if req.Action == "rotate" && b.ID == target.ID {
			c = rotated
		}
		candidate.Bindings = append(candidate.Bindings, b)
		candidate.Credentials = append(candidate.Credentials, c)
	}
	h, err := s.prepare(ctx, candidate)
	if err != nil {
		return op, err
	}
	actor, err := localActor()
	if err != nil {
		_ = h.Close(context.Background())
		return op, err
	}
	op, err = repo.BeginRuntimeOperation(ctx, req.Revision, actor, "runtime_replace")
	if err != nil {
		_ = h.Close(context.Background())
		return op, err
	}
	old := r.handles[id]
	if old == nil {
		_ = h.Close(context.Background())
		_ = repo.FailOperation(context.Background(), op)
		return op, identity.Err(identity.Unavailable, "committed runtime unavailable")
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Close(cleanup)
		_ = repo.FailOperation(cleanup, op)
		restored, e := s.prepare(cleanup, oldIntent)
		if e == nil {
			e = restored.Start(cleanup)
		}
		if e == nil {
			e = restored.Health(cleanup)
		}
		if e != nil {
			if restored != nil {
				_ = restored.Close(cleanup)
			}
			delete(r.handles, id)
			err = identity.Err(identity.Unavailable, "runtime rollback requires recovery")
			return
		}
		restored.Activate()
		r.handles[id] = restored
	}()
	if err = old.Close(ctx); err != nil {
		return op, err
	}
	delete(r.handles, id)
	if err = h.Start(ctx); err == nil {
		err = h.Health(ctx)
	}
	if err != nil {
		return op, err
	}
	err = repo.CommitOperation(ctx, op, func(w ports.Writer) error {
		if req.Action != "" {
			uw, ok := w.(ports.UserWriter)
			if !ok {
				return identity.Err(identity.NotImplemented, "user writer unavailable")
			}
			if req.Action == "delete" {
				return uw.DeleteBindingUser(*target, req.ResourceRevision)
			}
			return uw.RotateBindingCredential(*target, rotated, req.ResourceRevision)
		}
		bw, ok := w.(ports.BindingWriter)
		if !ok {
			return identity.Err(identity.NotImplemented, "binding writer unavailable")
		}
		return bw.SetBindingEnabled(req.BindingID, req.Enabled, req.ResourceRevision)
	})
	if err != nil {
		return op, safeOperation(err)
	}
	committed = true
	h.Activate()
	r.handles[id] = h
	_ = op.Finish(identity.Committed, time.Now(), "")
	return op, nil
}
