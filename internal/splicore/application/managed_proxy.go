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

type ManagedProxyLifecycleRequest struct {
	Action           string            `json:"action"`
	ResourceRevision identity.Revision `json:"resource_revision"`
	Revision         identity.Revision `json:"revision"`
}

type ManagedProxyCommands interface {
	SetManagedProxyLifecycle(context.Context, identity.ID, ManagedProxyLifecycleRequest) (identity.Transaction, error)
}

type SOCKS5LifecycleRequest = ManagedProxyLifecycleRequest

type SOCKS5Commands interface {
	SetSOCKS5Lifecycle(context.Context, identity.ID, SOCKS5LifecycleRequest) (identity.Transaction, error)
}

func managedProxy(in access.Inbound) bool {
	return proxy.IsManagedInbound(in.Protocol)
}

func (s *Service) SetSOCKS5Lifecycle(ctx context.Context, id identity.ID, req SOCKS5LifecycleRequest) (identity.Transaction, error) {
	return s.setManagedProxyLifecycle(ctx, id, req, true)
}

func (s *Service) SetManagedProxyLifecycle(ctx context.Context, id identity.ID, req ManagedProxyLifecycleRequest) (identity.Transaction, error) {
	return s.setManagedProxyLifecycle(ctx, id, req, false)
}

func (s *Service) setManagedProxyLifecycle(ctx context.Context, id identity.ID, req ManagedProxyLifecycleRequest, socks5Only bool) (op identity.Transaction, err error) {
	if id.Validate() != nil || req.Action != "start" && req.Action != "stop" && req.Action != "delete" {
		return op, identity.Err(identity.Invalid, "invalid managed proxy lifecycle request")
	}
	if s.runtime == nil {
		return op, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return op, identity.Err(identity.Unavailable, "runtime closed")
	}
	repo, ok := r.repo.(ports.MultiBindingRepository)
	if !ok {
		return op, identity.Err(identity.NotImplemented, "managed proxy lifecycle unavailable")
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
	index := slices.IndexFunc(all, func(in access.Inbound) bool { return in.ID == id })
	if index < 0 {
		return op, identity.Err(identity.NotFound, "inbound not found")
	}
	in := all[index]
	if !managedProxy(in) || socks5Only && in.Protocol != proxy.Key("socks5") {
		return op, identity.Err(identity.NotImplemented, "lifecycle operation requires a matching managed proxy inbound")
	}
	if in.Revision != req.ResourceRevision {
		return op, identity.RevisionConflict(in.Revision)
	}

	var bindings []access.Binding
	if req.Action == "delete" {
		if clientRepo, ok := r.repo.(ports.ClientRepository); ok {
			client, err := clientRepo.ClientState(ctx)
			if err != nil {
				return op, err
			}
			for _, rule := range client.Network.Route.Rules {
				if slices.Contains(rule.Match.ServerInbounds, id) {
					return op, identity.Err(identity.Conflict, "inbound is referenced by a route rule")
				}
			}
		}
		bindings, err = repo.Bindings(ctx, id)
		if err != nil {
			return op, err
		}
	}
	write := func(w ports.Writer) error {
		managed, ok := w.(ports.ManagedProxyLifecycleWriter)
		if !ok {
			return identity.Err(identity.NotImplemented, "managed proxy lifecycle writer unavailable")
		}
		if req.Action == "delete" {
			return managed.DeleteManagedProxyInbound(in, bindings)
		}
		return managed.SetManagedProxyInboundEnabled(in, req.Action == "start")
	}

	handle := r.handles[id]
	if req.Action == "start" {
		if handle != nil {
			if handle.Health(ctx) == nil {
				return op, identity.Err(identity.Conflict, "managed proxy inbound already running")
			}
			if err := handle.Close(ctx); err != nil {
				return op, err
			}
			delete(r.handles, id)
		}
		in.Enabled = true
		intent, err := s.projection(ctx, in, req.Revision)
		if err != nil {
			return op, err
		}
		return s.commitCandidate(ctx, intent, func(ctx context.Context, rev identity.Revision, actor identity.Actor) (identity.Transaction, error) {
			return repo.BeginRuntimeOperation(ctx, rev, actor, "runtime_replace")
		}, write)
	}

	// A stopped generation has no sockets to replace.
	if handle == nil {
		return commitManagedProxyWrite(ctx, repo, req.Revision, write)
	}
	intent, err := s.projection(ctx, in, req.Revision)
	if err != nil {
		return op, err
	}
	actor, err := localActor()
	if err != nil {
		return op, err
	}
	op, err = repo.BeginRuntimeOperation(ctx, req.Revision, actor, "runtime_replace")
	if err != nil {
		return op, err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = repo.FailOperation(cleanup, op)
		restored, restoreErr := s.prepare(cleanup, intent)
		if restoreErr == nil {
			restoreErr = restored.Start(cleanup)
		}
		if restoreErr == nil {
			restoreErr = restored.Health(cleanup)
		}
		if restoreErr != nil {
			if restored != nil {
				_ = restored.Close(cleanup)
			}
			err = identity.Err(identity.Unavailable, "managed proxy runtime rollback requires recovery")
			return
		}
		restored.Activate()
		r.handles[id] = restored
	}()
	delete(r.handles, id)
	if err = handle.Close(ctx); err != nil {
		return op, err
	}
	if err = repo.CommitOperation(ctx, op, write); err != nil {
		return op, safeOperation(err)
	}
	committed = true
	_ = op.Finish(identity.Committed, time.Now(), "")
	return op, nil
}

func commitManagedProxyWrite(ctx context.Context, repo ports.MultiBindingRepository, revision identity.Revision, write func(ports.Writer) error) (identity.Transaction, error) {
	actor, err := localActor()
	if err != nil {
		return identity.Transaction{}, err
	}
	op, err := repo.BeginRuntimeOperation(ctx, revision, actor, "runtime_replace")
	if err != nil {
		return op, err
	}
	if err = repo.CommitOperation(ctx, op, write); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = repo.FailOperation(cleanup, op)
		return op, safeOperation(err)
	}
	_ = op.Finish(identity.Committed, time.Now(), "")
	return op, nil
}
