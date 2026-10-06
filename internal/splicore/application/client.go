package application

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/clientruntime"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"reflect"
	"sync"
	"time"
)

// CredentialInput is an explicit write-only secret boundary, never returned by queries.
type CredentialInput struct {
	Kind  access.CredentialKind `json:"kind"`
	Value string                `json:"value"`
}

func (c CredentialInput) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(secret.Redacted)) }

type ClientMutation struct {
	Host         *client.HostIntegration `json:"host_integration,omitempty"`
	Network      *P.Config               `json:"network,omitempty"`
	RouteRule    *P.RouteRule            `json:"route_rule,omitempty"`
	RuleSet      *P.RuleSet              `json:"rule_set,omitempty"`
	PolicyGroup  *P.PolicyGroup          `json:"policy_group,omitempty"`
	DNSServer    *P.DNSServer            `json:"dns_server,omitempty"`
	DNSRule      *P.DNSRule              `json:"dns_rule,omitempty"`
	DNSProfile   *P.DNSProfile           `json:"dns_profile,omitempty"`
	RouteProfile *P.RouteProfile         `json:"route_profile,omitempty"`
	Selected     *P.Action               `json:"selected,omitempty"`
	Resource     string                  `json:"resource"`
	Action       string                  `json:"action"`
	ID           identity.ID             `json:"id,omitempty"`
	Node         *client.RemoteNode      `json:"node,omitempty"`
	Outbound     *client.Outbound        `json:"outbound,omitempty"`
	LocalInbound *client.LocalInbound    `json:"local_inbound,omitempty"`
	Route        *client.Route           `json:"route,omitempty"`
	Credential   *CredentialInput        `json:"credential,omitempty"`
}

func (m ClientMutation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("ClientMutation{" + secret.Redacted + "}"))
}

type ClientResult struct {
	ID          identity.ID          `json:"id,omitempty"`
	Transaction identity.Transaction `json:"transaction"`
}
type ClientCommands interface {
	ClientStatus(context.Context) (clientruntime.Status, error)
	ValidateClient(context.Context, json.RawMessage) error
	PlanClient(context.Context, json.RawMessage) (ports.ClientPlan, error)
	ApplyClient(context.Context, ApplyRequest) (ClientResult, error)
}
type clientState struct {
	management    *managementState
	mu            sync.Mutex
	repo          ports.ClientRepository
	factories     *registry.Outbounds
	manager       *clientruntime.Manager
	recoveryError string
	closed        bool
}

func (s *Service) WaitClientIdle(ctx context.Context) error {
	if s.client == nil {
		return identity.Err(identity.NotImplemented, "client runtime unavailable")
	}
	return s.client.manager.WaitIdle(ctx)
}

// EnableClientRuntime restores client state independently of server runtime health.
// A failed client listener is reported as degraded while server/API remain running.
func (s *Service) EnableClientRuntime(ctx context.Context, factories *registry.Outbounds, hostDirectory ...string) error {
	repo, ok := s.repo.(ports.ClientRepository)
	if !ok || s.runtime == nil || factories == nil {
		return identity.Err(identity.Unavailable, "client dependencies unavailable")
	}
	c := &clientState{repo: repo, factories: factories, manager: clientruntime.NewWithUnderlay(s.underlay), management: newManagementState()}
	s.client = c
	if len(hostDirectory) > 0 {
		if err := c.manager.ConfigureHost(ctx, hostDirectory[0]); err != nil {
			c.recoveryError = "host_recovery_failed"
		}
	}
	state, err := repo.ClientState(ctx)
	if err != nil {
		c.recoveryError = "client_committed_state_invalid"
		return nil
	}
	secrets, err := s.clientCredentials(ctx, state, nil)
	if err == nil {
		var p *clientruntime.Prepared
		p, err = c.manager.Prepare(ctx, state, secrets, factories)
		if err == nil {
			err = p.Activate()
		}
	}
	if err != nil {
		c.recoveryError = "client_recovery_failed"
	}
	return nil
}
func (s *Service) CloseClientRuntime(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	c := s.client
	if err := s.StopManagement(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return c.manager.Close(ctx)
}
func (s *Service) ClientStatus(ctx context.Context) (clientruntime.Status, error) {
	if s.client == nil {
		return clientruntime.Status{}, identity.Err(identity.NotImplemented, "client runtime unavailable")
	}
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := c.repo.ClientState(ctx)
	if err != nil {
		status := c.manager.Status(client.Empty(), c.factories.Capabilities())
		status.Health = "degraded"
		status.LastError = "client_committed_state_invalid"
		return status, nil
	}
	status := c.manager.Status(state, c.factories.Capabilities())
	if c.recoveryError != "" {
		status.Health = "degraded"
		status.LastError = c.recoveryError
	}
	return status, nil
}
func (s *Service) clientCredentials(ctx context.Context, state client.ProfileState, newCredentials []access.Credential) (map[identity.ID]access.Credential, error) {
	out := map[identity.ID]access.Credential{}
	for _, c := range newCredentials {
		out[c.ID] = c
	}
	for _, n := range state.Nodes {
		if _, ok := out[n.CredentialID]; ok {
			continue
		}
		c, err := s.client.repo.RevealCredential(ctx, n.CredentialID)
		if err != nil {
			return nil, err
		}
		if c.OwnerNodeID == nil || *c.OwnerNodeID != n.ID {
			return nil, identity.Err(identity.Invalid, "remote credential owner mismatch")
		}
		out[c.ID] = c
	}
	return out, nil
}

type clientCandidate struct {
	state    client.ProfileState
	secrets  []access.Credential
	id       identity.ID
	mutation ClientMutation
}

func (s *Service) clientCandidate(ctx context.Context, b json.RawMessage) (clientCandidate, error) {
	var out clientCandidate
	var m ClientMutation
	if err := StrictClientJSON(b, &m); err != nil {
		return out, err
	}
	out.mutation = m
	state, err := s.client.repo.ClientState(ctx)
	if err != nil {
		return out, err
	}
	out.state = state.Clone()
	invalid := func() (clientCandidate, error) {
		return clientCandidate{}, identity.Err(identity.Invalid, "invalid client command")
	}
	// Exact shapes keep secrets and protocol options out of unrelated mutation paths.
	count := 0
	for _, present := range []bool{m.Host != nil, m.Node != nil, m.Outbound != nil, m.LocalInbound != nil, m.Route != nil, m.Network != nil, m.RouteRule != nil, m.RuleSet != nil, m.PolicyGroup != nil, m.DNSServer != nil, m.DNSRule != nil, m.DNSProfile != nil, m.RouteProfile != nil, m.Selected != nil} {
		if present {
			count++
		}
	}
	if m.Action == "delete" && count != 0 {
		return invalid()
	}
	if m.Resource != "node" && m.Credential != nil {
		return invalid()
	}
	if m.Action == "create" && m.ID != "" {
		return invalid()
	}
	id := m.ID
	out.id = id
	switch m.Resource {
	case "node":
		pos := -1
		for i, n := range state.Nodes {
			if n.ID == id {
				pos = i
			}
		}
		switch m.Action {
		case "create", "update":
			if m.Node == nil || count != 1 {
				return invalid()
			}
			n := *m.Node
			if m.Action == "create" && (n.Provenance.ProviderID != "" || n.Provenance.Key != "") {
				return invalid()
			}
			if m.Action == "create" {
				if n.ID == "" {
					n.ID, err = identity.NewID()
					if err != nil {
						return out, err
					}
				}
				for _, old := range state.Nodes {
					if old.ID == n.ID {
						return invalid()
					}
				}
			} else {
				if pos < 0 {
					return out, identity.Err(identity.NotFound, "node not found")
				}
				if n.ID != id || n.CredentialID != state.Nodes[pos].CredentialID || m.Credential != nil {
					return invalid()
				}
				if !reflect.DeepEqual(n.Provenance, state.Nodes[pos].Provenance) {
					return invalid()
				}
				if state.Nodes[pos].Provenance.ProviderID != "" && (!reflect.DeepEqual(n.Protocol, state.Nodes[pos].Protocol) || !reflect.DeepEqual(n.Endpoint, state.Nodes[pos].Endpoint) || !reflect.DeepEqual(n.Options, state.Nodes[pos].Options) || !reflect.DeepEqual(n.Security, state.Nodes[pos].Security) || !reflect.DeepEqual(n.Transport, state.Nodes[pos].Transport)) {
					return invalid()
				}
			}
			if m.Credential != nil {
				if n.CredentialID != "" {
					return invalid()
				}
				n.CredentialID, err = identity.NewID()
				if err != nil {
					return out, err
				}
				c, err := remoteCredential(n.ID, n.CredentialID, *m.Credential)
				if err != nil {
					return out, err
				}
				out.secrets = append(out.secrets, c)
			}
			if m.Action == "create" {
				out.state.Nodes = append(out.state.Nodes, n)
			} else {
				out.state.Nodes[pos] = n
			}
			out.id = n.ID
		case "rotate":
			if pos < 0 {
				return out, identity.Err(identity.NotFound, "node not found")
			}
			if count != 0 || m.Credential == nil {
				return invalid()
			}
			n := state.Nodes[pos]
			if n.Provenance.ProviderID != "" {
				return invalid()
			}
			n.CredentialID, err = identity.NewID()
			if err != nil {
				return out, err
			}
			c, err := remoteCredential(n.ID, n.CredentialID, *m.Credential)
			if err != nil {
				return out, err
			}
			out.secrets = append(out.secrets, c)
			out.state.Nodes[pos] = n
		case "delete":
			if pos < 0 {
				return out, identity.Err(identity.NotFound, "node not found")
			}
			if m.Credential != nil {
				return invalid()
			}
			if state.Nodes[pos].Provenance.ProviderID != "" {
				return invalid()
			}
			for _, o := range state.Outbounds {
				if o.NodeID != nil && *o.NodeID == id {
					return invalid()
				}
			}
			out.state.Nodes = append(out.state.Nodes[:pos], out.state.Nodes[pos+1:]...)
		default:
			return invalid()
		}
	case "outbound":
		pos := -1
		for i, o := range state.Outbounds {
			if o.ID == id {
				pos = i
			}
		}
		switch m.Action {
		case "create", "update":
			if m.Outbound == nil || count != 1 {
				return invalid()
			}
			o := *m.Outbound
			if m.Action == "create" {
				if o.ProviderID != "" {
					return invalid()
				}
				if o.ID == "" {
					o.ID, err = identity.NewID()
					if err != nil {
						return out, err
					}
				}
				for _, old := range state.Outbounds {
					if old.ID == o.ID {
						return invalid()
					}
				}
				out.state.Outbounds = append(out.state.Outbounds, o)
			} else {
				if pos < 0 {
					return out, identity.Err(identity.NotFound, "outbound not found")
				}
				if o.ID != id {
					return invalid()
				}
				if o.ProviderID != state.Outbounds[pos].ProviderID {
					return invalid()
				}
				out.state.Outbounds[pos] = o
			}
			out.id = o.ID
		case "delete":
			if pos < 0 {
				return out, identity.Err(identity.NotFound, "outbound not found")
			}
			if id == client.Direct {
				return invalid()
			}
			out.state.Outbounds = append(out.state.Outbounds[:pos], out.state.Outbounds[pos+1:]...)
		default:
			return invalid()
		}
	case "local-inbound":
		pos := -1
		for i, o := range state.LocalInbounds {
			if o.ID == id {
				pos = i
			}
		}
		switch m.Action {
		case "create", "update":
			if m.LocalInbound == nil || count != 1 {
				return invalid()
			}
			i := *m.LocalInbound
			i.Defaults()
			if m.Action == "create" {
				if i.ID == "" {
					i.ID, err = identity.NewID()
					if err != nil {
						return out, err
					}
				}
				for _, old := range state.LocalInbounds {
					if old.ID == i.ID {
						return invalid()
					}
				}
				out.state.LocalInbounds = append(out.state.LocalInbounds, i)
			} else {
				if pos < 0 {
					return out, identity.Err(identity.NotFound, "local inbound not found")
				}
				if i.ID != id {
					return invalid()
				}
				out.state.LocalInbounds[pos] = i
			}
			out.id = i.ID
		case "delete":
			if pos < 0 {
				return out, identity.Err(identity.NotFound, "local inbound not found")
			}
			out.state.LocalInbounds = append(out.state.LocalInbounds[:pos], out.state.LocalInbounds[pos+1:]...)
		default:
			return invalid()
		}
	case "route":
		if m.Action != "update" || m.Route == nil || count != 1 || id != "" {
			return invalid()
		}
		out.state.Route = *m.Route
	case "host-integration":
		if m.Action != "update" || m.Host == nil || count != 1 || id != "" {
			return invalid()
		}
		out.state.Host = *m.Host
	case "host-network":
		if m.Action != "repair" || count != 0 || id != "" {
			return invalid()
		}
	case "runtime":
		if count != 0 || id != "" {
			return invalid()
		}
		switch m.Action {
		case "start", "restart":
			out.state.Enabled = true
		case "stop":
			out.state.Enabled = false
		default:
			return invalid()
		}
	case "network", "route-rule", "rule-set", "policy-group", "dns-server", "dns-rule", "dns-profile", "route-profile":
		if err = mutateNetwork(&out.state.Network, m, count, &out.id); err != nil {
			return out, err
		}
	default:
		return invalid()
	}
	if err = out.state.Validate(); err != nil {
		return out, err
	}
	// Provider-owned rule content is updated through its generation transaction.
	// Manual routing changes can reference it but cannot overwrite or remove it.
	for _, p := range state.Management.Providers {
		if p.Kind != "ruleset" || p.Generation == 0 {
			continue
		}
		var oldSet, newSet P.RuleSet
		for _, x := range state.Network.RuleSets {
			if x.ID == p.RuleSetID {
				oldSet = x
			}
		}
		for _, x := range out.state.Network.RuleSets {
			if x.ID == p.RuleSetID {
				newSet = x
			}
		}
		if !reflect.DeepEqual(oldSet, newSet) {
			return invalid()
		}
	}
	credentials, err := s.clientCredentials(ctx, out.state, out.secrets)
	if err != nil {
		return out, err
	}
	err = clientruntime.Validate(out.state, credentials, s.client.factories)
	return out, err
}
func remoteCredential(node, id identity.ID, input CredentialInput) (access.Credential, error) {
	// Payload decoding is the shared credential-kind boundary, not protocol dispatch.
	payload, err := access.DecodeRemotePayload(input.Kind, input.Value)
	if err != nil {
		return access.Credential{}, err
	}
	c := access.Credential{ID: id, OwnerNodeID: &node, Kind: input.Kind, Schema: 1, State: "active", Payload: payload, Stamp: identity.NewStamp(time.Now())}
	return c, c.Validate()
}
func (s *Service) ValidateClient(ctx context.Context, b json.RawMessage) error {
	_, err := s.PlanClient(ctx, b)
	return err
}
func (s *Service) PlanClient(ctx context.Context, b json.RawMessage) (ports.ClientPlan, error) {
	if s.client == nil {
		return ports.ClientPlan{}, identity.Err(identity.NotImplemented, "client runtime unavailable")
	}
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ports.ClientPlan{}, identity.Err(identity.Unavailable, "client runtime closed")
	}
	candidate, err := s.clientCandidate(ctx, b)
	if err != nil {
		return ports.ClientPlan{}, err
	}
	return ports.ClientPlan{Revision: candidate.state.Revision, Digest: s.creationDigest("client", b, candidate.state.Revision), Resource: candidate.mutation.Resource, Action: candidate.mutation.Action}, nil
}
func (s *Service) ApplyClient(ctx context.Context, req ApplyRequest) (result ClientResult, err error) {
	if s.client == nil {
		return result, identity.Err(identity.NotImplemented, "client runtime unavailable")
	}
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return result, identity.Err(identity.Unavailable, "client runtime closed")
	}
	if len(req.Digest) != 64 || !hmac.Equal([]byte(req.Digest), []byte(s.creationDigest("client", req.Document, req.Revision))) {
		return result, identity.Err(identity.Invalid, "invalid client plan")
	}
	candidate, err := s.clientCandidate(ctx, req.Document)
	if err != nil {
		return result, err
	}
	if candidate.state.Revision != req.Revision {
		return result, identity.RevisionConflict(candidate.state.Revision)
	}
	actor, err := localActor()
	if err != nil {
		return result, err
	}
	op, err := c.repo.BeginOperation(ctx, req.Revision, actor)
	if err != nil {
		return result, err
	}
	candidate.state.Revision = op.TargetRevision
	committed := false
	var prepared *clientruntime.Prepared
	defer func() {
		if !committed {
			if prepared != nil {
				err = errors.Join(err, prepared.Abort())
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = c.repo.FailOperation(cleanup, op)
		}
	}()
	credentials, err := s.clientCredentials(ctx, candidate.state, candidate.secrets)
	if err != nil {
		return result, err
	}
	restart := candidate.mutation.Resource == "runtime" && candidate.mutation.Action == "restart"
	if candidate.mutation.Resource == "host-network" {
		if err = c.manager.RepairHost(ctx); err != nil {
			return result, err
		}
	}
	prepared, err = c.manager.PrepareWithRestart(ctx, candidate.state, credentials, c.factories, restart)
	if err != nil {
		return result, err
	}
	err = c.repo.CommitOperation(ctx, op, func(w ports.Writer) error {
		cw, ok := w.(ports.ClientWriter)
		if !ok {
			return identity.Err(identity.Unavailable, "client storage unavailable")
		}
		return cw.ReplaceClient(candidate.state, candidate.secrets)
	})
	if err != nil {
		return result, err
	}
	committed = true
	err = prepared.Activate()
	if err != nil {
		c.recoveryError = "host_activation_degraded"
		_ = op.Finish(identity.Committed, time.Now(), "")
		return ClientResult{ID: candidate.id, Transaction: op}, err
	}
	c.recoveryError = ""
	_ = op.Finish(identity.Committed, time.Now(), "")
	return ClientResult{ID: candidate.id, Transaction: op}, nil
}
