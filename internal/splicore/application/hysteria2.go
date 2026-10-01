package application

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/policy"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	hm "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	"net/netip"
	"time"
)

type PolicyDraft struct {
	QuotaBytes  *int64 `json:"quota_bytes,omitempty"`
	UploadBps   *int64 `json:"upload_bps,omitempty"`
	DownloadBps *int64 `json:"download_bps,omitempty"`
}
type Hysteria2User struct {
	Name     string
	Enabled  bool
	Password secret.Value
	Policy   *PolicyDraft
}
type Hysteria2Document struct {
	Schema            int
	Name              string
	Listener, Display access.Endpoint
	Settings          hm.Settings
	Users             []Hysteria2User
}

func (Hysteria2Document) Format(s fmt.State, v rune) {
	_, _ = s.Write([]byte("Hysteria2Document{[REDACTED]}"))
}

type Hysteria2Plan struct {
	Digest          string            `json:"digest"`
	Revision        identity.Revision `json:"revision"`
	Listener        access.Endpoint   `json:"listener"`
	Display         access.Endpoint   `json:"display_endpoint"`
	Users           int               `json:"users"`
	TLSVerification bool              `json:"tls_verification"`
	PolicyEnforced  bool              `json:"policy_enforced"`
}
type Hysteria2ApplyResult struct {
	InboundID   identity.ID          `json:"inbound_id"`
	Bindings    []BindingView        `json:"bindings"`
	Transaction identity.Transaction `json:"transaction"`
}
type BindingRequest struct {
	BindingID        identity.ID       `json:"binding_id"`
	Enabled          bool              `json:"enabled"`
	ResourceRevision identity.Revision `json:"resource_revision"`
	Revision         identity.Revision `json:"revision"`
}
type Hysteria2Commands interface {
	ValidateHysteria2(context.Context, json.RawMessage) error
	PlanHysteria2(context.Context, json.RawMessage) (Hysteria2Plan, error)
	ApplyHysteria2(context.Context, ApplyRequest) (Hysteria2ApplyResult, error)
	SetBinding(context.Context, identity.ID, BindingRequest) (identity.Transaction, error)
}

func DecodeHysteria2(b []byte) (Hysteria2Document, error) {
	var w struct {
		Schema     int             `json:"schema"`
		Name       string          `json:"name"`
		Listener   access.Endpoint `json:"listener"`
		Display    access.Endpoint `json:"display_endpoint"`
		Settings   json.RawMessage `json:"settings"`
		PolicyMode string          `json:"policy_mode,omitempty"`
		Users      []struct {
			Name     string          `json:"account_name"`
			Enabled  *bool           `json:"enabled,omitempty"`
			Password json.RawMessage `json:"password"`
			Policy   *PolicyDraft    `json:"traffic_policy,omitempty"`
		} `json:"users"`
	}
	invalid := func() (Hysteria2Document, error) {
		return Hysteria2Document{}, identity.Err(identity.Invalid, "invalid Hysteria2 document")
	}
	if StrictJSON(b, &w) != nil || w.Schema != 1 || !identity.Label(w.Name, 128) || len(w.Users) < 1 || len(w.Users) > 16 || w.Listener.Validate() != nil || w.Display.Validate() != nil {
		return invalid()
	}
	if ip, err := netip.ParseAddr(w.Listener.Host); err != nil || ip.Zone() != "" {
		return invalid()
	}
	settings, err := hm.Decode(w.Settings)
	if err != nil {
		return invalid()
	}
	if w.PolicyMode != "" && w.PolicyMode != "metadata_only" {
		return invalid()
	}
	d := Hysteria2Document{Schema: w.Schema, Name: w.Name, Listener: w.Listener, Display: w.Display, Settings: settings}
	names, passwords := map[string]bool{}, map[string]bool{}
	for _, u := range w.Users {
		if !identity.Label(u.Name, 128) || names[u.Name] {
			return invalid()
		}
		names[u.Name] = true
		enabled := true
		if u.Enabled != nil {
			enabled = *u.Enabled
		}
		var pass string
		if len(u.Password) > 0 {
			if json.Unmarshal(u.Password, &pass) != nil || hm.ValidatePassword(secret.New(pass)) != nil || passwords[pass] {
				return invalid()
			}
			passwords[pass] = true
		}
		if u.Policy != nil {
			if w.PolicyMode != "metadata_only" {
				return invalid()
			}
			for _, n := range []*int64{u.Policy.QuotaBytes, u.Policy.UploadBps, u.Policy.DownloadBps} {
				if n != nil && *n < 0 {
					return invalid()
				}
			}
		}
		d.Users = append(d.Users, Hysteria2User{Name: u.Name, Enabled: enabled, Password: secret.New(pass), Policy: u.Policy})
	}
	return d, nil
}
func (s *Service) ValidateHysteria2(_ context.Context, b json.RawMessage) error {
	_, err := DecodeHysteria2(b)
	return err
}
func (s *Service) PlanHysteria2(ctx context.Context, b json.RawMessage) (Hysteria2Plan, error) {
	d, err := DecodeHysteria2(b)
	if err != nil {
		return Hysteria2Plan{}, err
	}
	if s.runtime == nil {
		return Hysteria2Plan{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	state, err := s.repo.State(ctx)
	if err != nil {
		return Hysteria2Plan{}, err
	}
	return Hysteria2Plan{Digest: s.digest(b, state.Revision), Revision: state.Revision, Listener: d.Listener, Display: d.Display, Users: len(d.Users), TLSVerification: true}, nil
}

type hysteriaResources struct {
	inbound     access.Inbound
	accounts    []access.Account
	bindings    []access.Binding
	credentials []access.Credential
	policies    []policy.TrafficPolicy
}

func (s *Service) hysteriaResources(d Hysteria2Document, node identity.ID) (hysteriaResources, error) {
	out := hysteriaResources{}
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
	data, _ := json.Marshal(d.Settings)
	out.inbound = access.Inbound{ID: id, NodeID: node, Name: d.Name, Protocol: hm.Key(), Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: listener, Transport: "udp", Endpoint: d.Listener}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: display, Endpoint: d.Display}}, Tags: []string{}, Settings: access.Settings{Schema: 1, Data: data}, Stamp: stamp}
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
		password := u.Password
		if password.Empty() {
			password, err = hm.GeneratePassword()
			if err != nil {
				return out, err
			}
		}
		a := access.Account{ID: aid, Name: u.Name, Status: access.Active, Enabled: true, Metadata: identity.Metadata{}, Stamp: stamp}
		b := access.Binding{ID: bid, AccountID: aid, InboundID: id, CredentialID: cid, Enabled: u.Enabled, Stamp: stamp}
		c := access.Credential{ID: cid, OwnerAccountID: &a.ID, Kind: access.Password, Schema: 1, State: "active", Payload: access.PasswordPayload{Password: password}, Stamp: stamp}
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
func (res hysteriaResources) intent(revision identity.Revision) ports.RuntimeIntent {
	in := ports.RuntimeIntent{Inbound: res.inbound, Revision: revision}
	for n, b := range res.bindings {
		if b.Enabled {
			in.Bindings = append(in.Bindings, b)
			in.Credentials = append(in.Credentials, res.credentials[n])
		}
	}
	return in
}
func (s *Service) ApplyHysteria2(ctx context.Context, req ApplyRequest) (Hysteria2ApplyResult, error) {
	var out Hysteria2ApplyResult
	if s.runtime == nil {
		return out, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return out, identity.Err(identity.Unavailable, "runtime closed")
	}
	d, err := DecodeHysteria2(req.Document)
	if err != nil {
		return out, err
	}
	if len(req.Digest) != 64 || !hmac.Equal([]byte(req.Digest), []byte(s.digest(req.Document, req.Revision))) {
		return out, identity.Err(identity.Invalid, "plan digest mismatch or daemon restarted")
	}
	repo, ok := r.repo.(ports.MultiBindingRepository)
	if !ok {
		return out, identity.Err(identity.NotImplemented, "multi-binding repository unavailable")
	}
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
	res, err := s.hysteriaResources(d, state.NodeID)
	if err != nil {
		return out, err
	}
	op, err := s.commitCandidate(ctx, res.intent(req.Revision), func(ctx context.Context, rev identity.Revision, a identity.Actor) (identity.Transaction, error) {
		return repo.BeginRuntimeOperation(ctx, rev, a, "runtime_create")
	}, func(w ports.Writer) error {
		if err := w.CreateInbound(res.inbound); err != nil {
			return err
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
	if err != nil || p.Capabilities(ports.CapabilityContext{}).Mutation.Users != ports.Restart {
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
	oldIntent, err := s.projection(ctx, i, state.Revision)
	if err != nil {
		return op, err
	}
	target.Enabled = req.Enabled
	candidate := ports.RuntimeIntent{Inbound: i, Revision: state.Revision}
	for _, b := range bs {
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
