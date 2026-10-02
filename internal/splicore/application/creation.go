package application

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/policy"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"time"
)

type CreationPlan struct {
	Protocol        access.ProtocolKey `json:"protocol"`
	Engine          string             `json:"engine"`
	Digest          string             `json:"digest"`
	Revision        identity.Revision  `json:"revision"`
	Listener        access.Endpoint    `json:"listener"`
	Display         access.Endpoint    `json:"display_endpoint"`
	Users           int                `json:"users"`
	TLSVerification bool               `json:"tls_verification"`
	PolicyEnforced  bool               `json:"policy_enforced"`
}
type CreationResult struct {
	InboundID   identity.ID          `json:"inbound_id"`
	Bindings    []BindingView        `json:"bindings"`
	Transaction identity.Transaction `json:"transaction"`
}

type CreationCommands interface {
	ValidateCreation(context.Context, string, json.RawMessage) error
	PlanCreation(context.Context, string, json.RawMessage) (CreationPlan, error)
	ApplyCreation(context.Context, string, ApplyRequest) (CreationResult, error)
}
type BindingCommands interface {
	SetBinding(context.Context, identity.ID, BindingRequest) (identity.Transaction, error)
}

func (s *Service) creationDraft(protocol string, b json.RawMessage) (ports.CreationDraft, error) {
	return s.protocols.DecodeCreation(s.engines, protocol, b)
}
func (s *Service) ValidateCreation(ctx context.Context, protocol string, b json.RawMessage) error {
	d, err := s.creationDraft(protocol, b)
	if err != nil {
		return err
	}
	return s.engineAvailability(ctx, d.Engine)
}
func (s *Service) engineAvailability(ctx context.Context, id string) error {
	e, err := s.engines.Get(id)
	if err != nil {
		return err
	}
	if a, ok := e.(ports.EngineAvailability); ok {
		return a.ValidateAvailability(ctx)
	}
	return nil
}
func (s *Service) creationDigest(protocol string, b json.RawMessage, r identity.Revision) string {
	data, _ := json.Marshal(struct {
		Protocol string          `json:"protocol"`
		Document json.RawMessage `json:"document"`
	}{protocol, b})
	return s.digest(data, r)
}
func (s *Service) PlanCreation(ctx context.Context, protocol string, b json.RawMessage) (CreationPlan, error) {
	d, err := s.creationDraft(protocol, b)
	if err != nil {
		return CreationPlan{}, err
	}
	if s.runtime == nil {
		return CreationPlan{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	if err = s.engineAvailability(ctx, d.Engine); err != nil {
		return CreationPlan{}, err
	}
	state, err := s.repo.State(ctx)
	if err != nil {
		return CreationPlan{}, err
	}
	return CreationPlan{Protocol: d.Protocol, Engine: d.Engine, Digest: s.creationDigest(protocol, b, state.Revision), Revision: state.Revision, Listener: d.Listener, Display: d.Display, Users: len(d.Users), TLSVerification: d.TLSVerification}, nil
}

type creationResources struct {
	inbound           access.Inbound
	accounts          []access.Account
	bindings          []access.Binding
	credentials       []access.Credential
	serverCredentials []access.Credential
	policies          []policy.TrafficPolicy
}

func (s *Service) creationResources(d ports.CreationDraft, node identity.ID, codec ports.CreationCodec) (creationResources, error) {
	out := creationResources{}
	if materializer, ok := codec.(ports.ServerMaterializer); ok {
		var err error
		d, err = materializer.MaterializeCreation(d)
		if err != nil {
			return out, err
		}
	}
	stamp := identity.NewStamp(time.Now())
	newID := identity.NewID
	id, err := newID()
	if err != nil {
		return out, err
	}
	listener, err := newID()
	if err != nil {
		return out, err
	}
	display, err := newID()
	if err != nil {
		return out, err
	}
	data := d.Settings
	out.inbound = access.Inbound{ID: id, NodeID: node, Name: d.Name, Protocol: d.Protocol, Engine: d.Engine, Enabled: true, Listeners: []access.Listener{{ID: listener, Transport: d.Transport, Endpoint: d.Listener}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: display, Endpoint: d.Display}}, Tags: []string{}, Settings: access.Settings{Schema: 1, Data: data}, Stamp: stamp}
	for _, payload := range d.ServerPayloads {
		cid, err := newID()
		if err != nil {
			return out, err
		}
		out.serverCredentials = append(out.serverCredentials, access.Credential{ID: cid, OwnerInboundID: &out.inbound.ID, Kind: payload.Kind(), Schema: 1, State: "active", Payload: payload, Stamp: stamp})
	}
	for _, u := range d.Users {
		aid, err := newID()
		if err != nil {
			return out, err
		}
		bid, err := newID()
		if err != nil {
			return out, err
		}
		cid, err := newID()
		if err != nil {
			return out, err
		}
		payload, err := codec.GenerateCreationCredential(u.Payload)
		if err != nil {
			return out, err
		}
		a := access.Account{ID: aid, Name: u.Name, Status: access.Active, Enabled: u.AccountEnabled, Metadata: identity.Metadata{}, Stamp: stamp}
		b := access.Binding{ID: bid, AccountID: aid, InboundID: id, CredentialID: cid, Enabled: u.Enabled, Stamp: stamp}
		c := access.Credential{ID: cid, OwnerAccountID: &a.ID, Kind: payload.Kind(), Schema: 1, State: "active", Payload: payload, Stamp: stamp}
		if u.Policy != nil {
			pid, err := newID()
			if err != nil {
				return out, err
			}
			b.PolicyOverrideID = &pid
			out.policies = append(out.policies, policy.TrafficPolicy{ID: pid, QuotaBytes: u.Policy.QuotaBytes, UploadBps: u.Policy.UploadBps, DownloadBps: u.Policy.DownloadBps, Stamp: stamp})
		}
		out.accounts = append(out.accounts, a)
		out.bindings = append(out.bindings, b)
		out.credentials = append(out.credentials, c)
	}
	return out, nil
}
func (res creationResources) intent(revision identity.Revision) ports.RuntimeIntent {
	in := ports.RuntimeIntent{Inbound: res.inbound, Revision: revision, ServerCredentials: res.serverCredentials}
	for n, b := range res.bindings {
		if b.Enabled && res.accounts[n].Enabled {
			in.Bindings = append(in.Bindings, b)
			in.Credentials = append(in.Credentials, res.credentials[n])
		}
	}
	return in
}
func (s *Service) ApplyCreation(ctx context.Context, protocol string, req ApplyRequest) (CreationResult, error) {
	var out CreationResult
	if s.runtime == nil {
		return out, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return out, identity.Err(identity.Unavailable, "runtime closed")
	}
	codec, err := s.protocols.Creation(protocol)
	if err != nil {
		return out, err
	}
	d, err := s.creationDraft(protocol, req.Document)
	if err != nil {
		return out, err
	}
	if err = s.engineAvailability(ctx, d.Engine); err != nil {
		return out, err
	}
	if len(req.Digest) != 64 || !hmac.Equal([]byte(req.Digest), []byte(s.creationDigest(protocol, req.Document, req.Revision))) {
		return out, identity.Err(identity.Invalid, "plan digest mismatch or daemon restarted")
	}
	repo := r.repo
	state, err := repo.State(ctx)
	if err != nil {
		return out, err
	}
	if state.Revision != req.Revision {
		return out, identity.RevisionConflict(state.Revision)
	}
	inbounds, err := repo.Inbounds(ctx)
	if err != nil {
		return out, err
	}
	if len(inbounds) >= 64 {
		return out, identity.Err(identity.Invalid, "at most 64 managed inbounds supported")
	}
	res, err := s.creationResources(d, state.NodeID, codec)
	if err != nil {
		return out, err
	}
	module, e := s.protocols.Get(d.Protocol)
	if e != nil {
		return out, e
	}
	for _, c := range res.credentials {
		if e = module.ValidateCredential(c); e != nil {
			return out, e
		}
	}
	op, err := s.commitCandidate(ctx, res.intent(req.Revision), func(ctx context.Context, rev identity.Revision, a identity.Actor) (identity.Transaction, error) {
		return repo.BeginOperation(ctx, rev, a)
	}, func(w ports.Writer) error {
		if err := w.CreateInbound(res.inbound); err != nil {
			return err
		}
		for _, c := range res.serverCredentials {
			if err := w.CreateCredential(c); err != nil {
				return err
			}
		}
		for _, p := range res.policies {
			if err := w.CreatePolicy(p); err != nil {
				return err
			}
		}
		for n, a := range res.accounts {
			if err := w.CreateAccount(a); err != nil {
				return err
			}
			if err := w.CreateCredential(res.credentials[n]); err != nil {
				return err
			}
			if err := w.CreateBinding(res.bindings[n]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	out.InboundID = res.inbound.ID
	out.Transaction = op
	for _, b := range res.bindings {
		out.Bindings = append(out.Bindings, BindingView{BindingID: b.ID, AccountID: b.AccountID, Enabled: b.Enabled, Revision: b.Revision, PolicyID: b.PolicyOverrideID})
	}
	return out, nil
}
