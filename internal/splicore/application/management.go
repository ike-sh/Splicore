package application

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/clientruntime"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/nodeimport"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"maps"
	"reflect"
	"slices"
	"time"
)

// ManagementRequest is write-only. Preview responses never serialize it.
type ManagementRequest struct {
	Operation         string             `json:"operation"`
	InputFormat       string             `json:"format,omitempty"`
	Content           string             `json:"content,omitempty"`
	Mode              string             `json:"mode,omitempty"`
	Provider          *provider.Provider `json:"provider,omitempty"`
	Source            *provider.Source   `json:"source,omitempty"`
	ID                identity.ID        `json:"id,omitempty"`
	IDs               []identity.ID      `json:"ids,omitempty"`
	Tags              []string           `json:"tags,omitempty"`
	Metadata          identity.Metadata  `json:"metadata,omitempty"`
	Action            string             `json:"action,omitempty"`
	GenerateOutbounds bool               `json:"generate_outbounds,omitempty"`
	Engine            string             `json:"engine,omitempty"`
}

func (ManagementRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("ManagementRequest{[REDACTED]}"))
}

type DiffEntry struct {
	Kind       string      `json:"kind"`
	ID         identity.ID `json:"id,omitempty"`
	Index      int         `json:"index,omitempty"`
	Change     string      `json:"change"`
	References int         `json:"references,omitempty"`
}
type ManagementPreview struct {
	Token       identity.ID       `json:"token,omitempty"`
	Revision    identity.Revision `json:"revision"`
	Expires     time.Time         `json:"expires"`
	Applicable  bool              `json:"applicable"`
	Reason      string            `json:"reason,omitempty"`
	Entries     []DiffEntry       `json:"entries"`
	ProviderID  identity.ID       `json:"provider_id,omitempty"`
	Generation  identity.Revision `json:"generation"`
	NotModified bool              `json:"not_modified,omitempty"`
}
type ManagementApply struct {
	Token    identity.ID       `json:"token"`
	Revision identity.Revision `json:"revision"`
}
type managementPlan struct {
	preview ManagementPreview
	state   client.ProfileState
	secrets []access.Credential
	sources map[identity.ID]provider.Source
}
type ManagementCommands interface {
	PreviewManagement(context.Context, ManagementRequest) (ManagementPreview, error)
	ApplyManagement(context.Context, ManagementApply) (ClientResult, error)
	PreviewProviderRefresh(context.Context, identity.ID) (ManagementPreview, error)
	RefreshProvider(context.Context, identity.ID) (ClientResult, error)
	ExportNodes(context.Context, NodeExportRequest) (NodeExport, error)
}

func managementInvalid() error { return identity.Err(identity.Invalid, "invalid management command") }
func newManagementPlan(state client.ProfileState) *managementPlan {
	return &managementPlan{preview: ManagementPreview{Revision: state.Revision, Expires: time.Now().Add(5 * time.Minute), Applicable: true, Entries: []DiffEntry{}}, state: state.Clone(), sources: map[identity.ID]provider.Source{}}
}
func (s *Service) saveManagementPlan(ctx context.Context, p *managementPlan) (ManagementPreview, error) {
	c := s.client
	if p.preview.Applicable {
		if e := p.state.Validate(); e != nil {
			p.preview.Applicable = false
			p.preview.Reason = "invalid_reference_or_dependency"
		} else {
			credentials, e := s.clientCredentials(ctx, p.state, p.secrets)
			if e != nil {
				return ManagementPreview{}, e
			}
			if e = clientruntime.Validate(p.state, credentials, c.factories); e != nil {
				p.preview.Applicable = false
				p.preview.Reason = "unsupported_or_invalid_runtime"
			}
		}
	}
	now := time.Now()
	for id, old := range c.management.plans {
		if now.After(old.preview.Expires) {
			delete(c.management.plans, id)
		}
	}
	if !p.preview.Applicable {
		return p.preview, nil
	}
	if len(c.management.plans) >= 32 {
		return ManagementPreview{}, identity.Err(identity.Unavailable, "management preview capacity reached")
	}
	token, e := identity.NewID()
	if e != nil {
		return ManagementPreview{}, e
	}
	p.preview.Token = token
	c.management.plans[token] = p
	view := p.preview
	view.Entries = slices.Clone(p.preview.Entries)
	return view, nil
}
func (s *Service) PreviewManagement(ctx context.Context, r ManagementRequest) (ManagementPreview, error) {
	if s.client == nil {
		return ManagementPreview{}, identity.Err(identity.NotImplemented, "client runtime unavailable")
	}
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ManagementPreview{}, identity.Err(identity.Unavailable, "client runtime closed")
	}
	state, e := c.repo.ClientState(ctx)
	if e != nil {
		return ManagementPreview{}, e
	}
	p := newManagementPlan(state)
	switch r.Operation {
	case "import":
		if r.Provider != nil || r.Source != nil || r.ID != "" || len(r.IDs) > 0 || len(r.Tags) > 0 || r.Metadata != nil || r.Action != "" {
			return ManagementPreview{}, managementInvalid()
		}
		if r.Mode == "" {
			r.Mode = "strict"
		}
		if r.Engine == "" {
			r.Engine = "native"
		}
		if r.Mode != "strict" && r.Mode != "lenient" || !identity.Label(r.Engine, 64) {
			return ManagementPreview{}, managementInvalid()
		}
		parsed, e := nodeimport.Parse(r.InputFormat, []byte(r.Content))
		if e != nil {
			return ManagementPreview{}, e
		}
		if e = s.diffNodes(ctx, p, parsed, nil, r.Mode, r.GenerateOutbounds, r.Engine); e != nil {
			return ManagementPreview{}, e
		}
	case "provider-upsert":
		if r.Provider == nil || r.Content != "" || r.InputFormat != "" || r.Mode != "" || len(r.IDs) > 0 || len(r.Tags) > 0 || r.Metadata != nil || r.Action != "" || r.GenerateOutbounds || r.Engine != "" {
			return ManagementPreview{}, managementInvalid()
		}
		next := *r.Provider
		if next.Generation != 0 || next.Status != "" || next.URLDisplay != "" || next.LastError != "" || next.Failures != 0 || !next.LastSuccess.IsZero() || !next.LastFailure.IsZero() {
			return ManagementPreview{}, managementInvalid()
		}
		pos := slices.IndexFunc(state.Management.Providers, func(x provider.Provider) bool { return x.ID == r.ID })
		if r.ID == "" {
			if next.ID != "" || r.Source == nil {
				return ManagementPreview{}, managementInvalid()
			}
			next.ID, e = identity.NewID()
			if e != nil {
				return ManagementPreview{}, e
			}
			if next.Kind == "ruleset" {
				if next.RuleSetID != "" {
					return ManagementPreview{}, managementInvalid()
				}
				next.RuleSetID, e = identity.NewID()
				if e != nil {
					return ManagementPreview{}, e
				}
			}
		} else {
			if pos < 0 {
				return ManagementPreview{}, identity.Err(identity.NotFound, "provider not found")
			}
			old := state.Management.Providers[pos]
			if next.ID != r.ID || next.Kind != old.Kind || next.RuleSetID != old.RuleSetID {
				return ManagementPreview{}, managementInvalid()
			}
			next.Generation = old.Generation
			next.Status = old.Status
			next.LastSuccess = old.LastSuccess
			next.LastFailure = old.LastFailure
			next.LastError = old.LastError
			next.Failures = old.Failures
			next.URLDisplay = old.URLDisplay
		}
		next.Defaults()
		if r.Source != nil {
			source := *r.Source
			if source.Auth != nil {
				auth := *source.Auth
				source.Auth = &auth
			}
			if source.ETag != "" || source.LastModified != "" || source.Validate() != nil {
				return ManagementPreview{}, managementInvalid()
			}
			next.URLDisplay = provider.RedactURL(source.URL)
			p.sources[next.ID] = source
		}
		if e = next.Validate(); e != nil {
			return ManagementPreview{}, e
		}
		kind := "Add"
		if pos < 0 {
			p.state.Management.Providers = append(p.state.Management.Providers, next)
		} else {
			kind = "Update"
			p.state.Management.Providers[pos] = next
		}
		p.preview.ProviderID = next.ID
		p.preview.Generation = next.Generation
		p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: kind, ID: next.ID, Change: "provider_config"})
	case "provider-delete":
		if r.ID.Validate() != nil || r.Provider != nil || r.Source != nil || r.Content != "" || r.InputFormat != "" || r.Mode != "" || len(r.IDs) > 0 || len(r.Tags) > 0 || r.Metadata != nil || r.Action != "" || r.GenerateOutbounds || r.Engine != "" {
			return ManagementPreview{}, managementInvalid()
		}
		pos := slices.IndexFunc(p.state.Management.Providers, func(x provider.Provider) bool { return x.ID == r.ID })
		if pos < 0 {
			return ManagementPreview{}, identity.Err(identity.NotFound, "provider not found")
		}
		old := p.state.Management.Providers[pos]
		if old.Kind == "ruleset" {
			refs := ruleSetReferences(p.state, old.RuleSetID)
			p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Remove", ID: old.RuleSetID, Change: "owned_rules", References: refs})
			if refs > 0 {
				p.preview.Applicable = false
				p.preview.Reason = "referenced_provider_resources"
			} else {
				p.state.Network.RuleSets = slices.DeleteFunc(p.state.Network.RuleSets, func(x P.RuleSet) bool { return x.ID == old.RuleSetID })
			}
		}
		p.state.Management.Providers = append(p.state.Management.Providers[:pos], p.state.Management.Providers[pos+1:]...)
		for _, n := range state.Nodes {
			if n.Provenance.ProviderID == r.ID {
				refs := nodeReferences(state, n.ID, r.ID)
				p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Remove", ID: n.ID, Change: "owned_node", References: refs})
				if refs > 0 {
					p.preview.Applicable = false
					p.preview.Reason = "referenced_provider_resources"
				} else {
					removeNode(&p.state, n.ID)
				}
			}
		}
		p.preview.ProviderID = r.ID
	case "batch":
		if r.ID != "" || r.Provider != nil || r.Source != nil || r.Content != "" || r.InputFormat != "" || r.Mode != "" || r.GenerateOutbounds || r.Engine != "" || len(r.IDs) == 0 || len(r.IDs) > provider.MaxNodes {
			return ManagementPreview{}, managementInvalid()
		}
		switch r.Action {
		case "enable", "disable", "delete", "tag", "metadata":
		default:
			return ManagementPreview{}, managementInvalid()
		}
		if r.Action != "tag" && len(r.Tags) > 0 {
			return ManagementPreview{}, managementInvalid()
		}
		if r.Action != "metadata" && r.Metadata != nil || r.Metadata.Validate() != nil {
			return ManagementPreview{}, managementInvalid()
		}
		seen := map[identity.ID]bool{}
		for _, id := range r.IDs {
			if seen[id] {
				return ManagementPreview{}, managementInvalid()
			}
			seen[id] = true
			pos := slices.IndexFunc(p.state.Nodes, func(n client.RemoteNode) bool { return n.ID == id })
			if pos < 0 {
				return ManagementPreview{}, identity.Err(identity.NotFound, "node not found")
			}
			n := &p.state.Nodes[pos]
			switch r.Action {
			case "enable":
				n.Disabled = false
			case "disable":
				n.Disabled = true
			case "tag":
				n.Tags = slices.Clone(r.Tags)
				slices.Sort(n.Tags)
			case "metadata":
				n.Metadata = maps.Clone(r.Metadata)
			case "delete":
				if n.Provenance.ProviderID != "" {
					p.preview.Applicable = false
					p.preview.Reason = "provider_owns_node"
				} else if nodeReferences(p.state, id, "") > 0 {
					p.preview.Applicable = false
					p.preview.Reason = "referenced_node"
				} else {
					removeNode(&p.state, id)
				}
			}
			p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Update", ID: id, Change: r.Action})
		}
	default:
		return ManagementPreview{}, managementInvalid()
	}
	return s.saveManagementPlan(ctx, p)
}

func payloadBytes(p access.Payload) []byte {
	switch x := p.(type) {
	case access.PSKPayload:
		return []byte(x.Key.Reveal())
	case access.PasswordPayload:
		return []byte(x.Password.Reveal())
	case access.UUIDPayload:
		return []byte(x.UUID.Reveal())
	case access.UUIDPasswordPayload:
		b, _ := json.Marshal([]string{x.UUID.Reveal(), x.Password.Reveal()})
		return b
	case access.UsernamePasswordPayload:
		b, _ := json.Marshal([]string{x.Username.Reveal(), x.Password.Reveal()})
		return b
	}
	return nil
}
func sameCredential(a, b access.Credential) bool {
	if a.Kind != b.Kind {
		return false
	}
	x, y := payloadBytes(a.Payload), payloadBytes(b.Payload)
	defer clear(x)
	defer clear(y)
	return hmac.Equal(x, y)
}
func (s *Service) diffNodes(ctx context.Context, p *managementPlan, parsed nodeimport.Result, owner *provider.Provider, mode string, generate bool, engine string) error {
	for _, issue := range parsed.Issues {
		p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: issue.Kind, Index: issue.Index, Change: issue.Code})
		if mode == "strict" {
			p.preview.Applicable = false
			p.preview.Reason = "strict_import_rejected"
		}
	}
	byKey := map[string]client.RemoteNode{}
	for _, n := range p.state.Nodes {
		if owner != nil && n.Provenance.ProviderID == owner.ID {
			if _, ok := byKey[n.Provenance.Key]; ok {
				return managementInvalid()
			}
			byKey[n.Provenance.Key] = n
		}
	}
	seen := map[string]access.Credential{}
	retained := map[identity.ID]bool{}
	oldCount := len(byKey)
	valid := 0
	for i, candidate := range parsed.Candidates {
		n := candidate.Node
		if n.ID != "" || n.CredentialID != "" || n.Provenance != (provider.Provenance{}) || n.State != "" || candidate.Key != "" && !identity.Label(candidate.Key, 120) {
			p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Invalid", Index: i + 1, Change: "invalid_candidate"})
			if mode == "strict" {
				p.preview.Applicable = false
				p.preview.Reason = "strict_import_rejected"
			}
			continue
		}
		key := nodeimport.LogicalKey(candidate)
		old, exists := byKey[key]
		if exists {
			n.ID = old.ID
		} else {
			var e error
			n.ID, e = identity.NewID()
			if e != nil {
				return e
			}
		}
		cid, e := identity.NewID()
		if e != nil {
			return e
		}
		n.CredentialID = cid
		cred, e := remoteCredential(n.ID, cid, CredentialInput{Kind: candidate.Credential.Kind, Value: candidate.Credential.Value})
		if e == nil {
			if owner != nil {
				n.Provenance = provider.Provenance{Origin: "provider", ProviderID: owner.ID, Key: key}
			} else if candidate.Origin == "uri" {
				n.Provenance = provider.Provenance{Origin: "uri"}
			} else {
				n.Provenance = provider.Provenance{Origin: "import"}
			}
			if e = n.Validate(); e == nil {
				f, err := s.client.factories.Get(n.Protocol.Protocol, engine)
				if err != nil {
					e = err
				} else {
					e = f.Validate(n, cred)
				}
			}
		}
		if e != nil {
			kind := "Invalid"
			var domain *identity.Error
			if errors.As(e, &domain) {
				switch domain.Code {
				case identity.UnsupportedExport, identity.UnsupportedEngineForProtocol, identity.UnsupportedEngineFeature, identity.UnsupportedPolicyForEngine:
					kind = "Unsupported"
				}
			}
			p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: kind, Index: i + 1, Change: "invalid_or_unsupported_node"})
			if mode == "strict" {
				p.preview.Applicable = false
				p.preview.Reason = "strict_import_rejected"
			}
			continue
		}
		valid++
		if prior, ok := seen[key]; ok {
			if sameCredential(prior, cred) {
				p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Unchanged", Index: i + 1, Change: "exact_duplicate"})
			} else {
				p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Conflict", Index: i + 1, Change: "ambiguous_identity"})
				p.preview.Applicable = false
				p.preview.Reason = "ambiguous_identity"
			}
			continue
		}
		seen[key] = cred
		kind, change := "Add", "node"
		if exists {
			if n.Protocol != old.Protocol {
				p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Conflict", ID: old.ID, Change: "protocol_replacement_requires_new_key"})
				p.preview.Applicable = false
				p.preview.Reason = "protocol_replacement"
				continue
			}
			retained[old.ID] = true
			n.Tags = slices.Clone(old.Tags)
			n.Metadata = maps.Clone(old.Metadata)
			n.Disabled = old.Disabled
			n.State = "active"
			stored, e := s.client.repo.RevealCredential(ctx, old.CredentialID)
			if e != nil {
				return e
			}
			rotated := !sameCredential(stored, cred)
			if !rotated {
				n.CredentialID = old.CredentialID
			} else {
				p.secrets = append(p.secrets, cred)
			}
			kind = "Update"
			change = "node_settings"
			if rotated {
				change = "credential_rotated"
			} else if old.Name != n.Name {
				change = "renamed"
			} else {
				compare := old
				compare.State = "active"
				if reflect.DeepEqual(compare, n) {
					kind = "Unchanged"
					change = "same_node"
				}
			}
			pos := slices.IndexFunc(p.state.Nodes, func(x client.RemoteNode) bool { return x.ID == old.ID })
			p.state.Nodes[pos] = n
			for j := range p.state.Outbounds {
				if o := &p.state.Outbounds[j]; o.ProviderID == owner.ID && o.NodeID != nil && *o.NodeID == n.ID {
					o.Name = n.Name
				}
			}
		} else {
			duplicate := false
			for _, old := range p.state.Nodes {
				if nodeimport.Fingerprint(old) == nodeimport.Fingerprint(n) {
					if owner == nil && old.Provenance.ProviderID == "" {
						stored, e := s.planCredential(ctx, p, old.CredentialID)
						if e != nil {
							return e
						}
						if sameCredential(stored, cred) {
							p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Unchanged", ID: old.ID, Index: i + 1, Change: "existing_manual_duplicate"})
							duplicate = true
							break
						}
					}
					if owner != nil && old.Provenance.ProviderID != owner.ID {
						p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Conflict", ID: old.ID, Index: i + 1, Change: "separate_source_ownership"})
					}
				}
			}
			if duplicate {
				continue
			}
			n.State = "active"
			p.state.Nodes = append(p.state.Nodes, n)
			p.secrets = append(p.secrets, cred)
		}
		if generate {
			has := slices.ContainsFunc(p.state.Outbounds, func(o client.Outbound) bool {
				return o.NodeID != nil && *o.NodeID == n.ID && o.Engine == engine && (owner == nil && o.ProviderID == "" || owner != nil && o.ProviderID == owner.ID)
			})
			if !has {
				oid, e := identity.NewID()
				if e != nil {
					return e
				}
				o := client.Outbound{ID: oid, Name: n.Name, Kind: "proxy", NodeID: &n.ID, Engine: engine}
				if owner != nil {
					o.ProviderID = owner.ID
				}
				p.state.Outbounds = append(p.state.Outbounds, o)
			}
		}
		p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: kind, ID: n.ID, Index: i + 1, Change: change})
	}
	if owner != nil {
		removed := 0
		keys := make([]string, 0, len(byKey))
		for key := range byKey {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			old := byKey[key]
			if !retained[old.ID] {
				removed++
				refs := nodeReferences(p.state, old.ID, owner.ID)
				if refs > 0 {
					pos := slices.IndexFunc(p.state.Nodes, func(n client.RemoteNode) bool { return n.ID == old.ID })
					p.state.Nodes[pos].State = "stale"
					p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Remove", ID: old.ID, Change: "retained_stale", References: refs})
				} else {
					removeNode(&p.state, old.ID)
					p.preview.Entries = append(p.preview.Entries, DiffEntry{Kind: "Remove", ID: old.ID, Change: "unreferenced_node"})
				}
			}
		}
		if valid == 0 && !owner.AllowEmpty || oldCount > 0 && removed*100 > oldCount*owner.MaxDeletePercent {
			p.preview.Applicable = false
			p.preview.Reason = "safety_guard"
		}
	}
	return nil
}
func (s *Service) planCredential(ctx context.Context, p *managementPlan, id identity.ID) (access.Credential, error) {
	for _, c := range p.secrets {
		if c.ID == id {
			return c, nil
		}
	}
	return s.client.repo.RevealCredential(ctx, id)
}
func outboundReferences(s client.ProfileState, id identity.ID) int {
	refs := 0
	if s.Route.DefaultOutbound == id {
		refs++
	}
	for _, i := range s.LocalInbounds {
		if i.SelectedOutbound == id {
			refs++
		}
	}
	check := func(a P.Action) {
		if a.Kind == P.Outbound && a.ID == id {
			refs++
		}
	}
	if s.Network.Route.Final != nil {
		check(*s.Network.Route.Final)
	}
	for _, r := range s.Network.Route.Rules {
		check(r.Action)
	}
	for _, g := range s.Network.Groups {
		for _, a := range g.Members {
			check(a)
		}
		if g.Selector != nil {
			check(g.Selector.Selected)
		}
	}
	for _, d := range s.Network.Servers {
		check(d.Detour)
	}
	for _, p := range s.Management.Providers {
		check(p.FetchAction)
	}
	return refs
}
func nodeReferences(s client.ProfileState, id, owner identity.ID) int {
	refs := 0
	for _, o := range s.Outbounds {
		if o.NodeID != nil && *o.NodeID == id {
			if owner == "" || o.ProviderID != owner {
				refs++
			}
			refs += outboundReferences(s, o.ID)
		}
	}
	return refs
}
func ruleSetReferences(s client.ProfileState, id identity.ID) int {
	refs := 0
	check := func(m P.RuleMatch) {
		for _, x := range m.RuleSets {
			if x == id {
				refs++
			}
		}
	}
	for _, r := range s.Network.Route.Rules {
		check(r.Match)
	}
	for _, r := range s.Network.DNSRules {
		check(r.Match)
	}
	for _, set := range s.Network.RuleSets {
		for _, r := range set.Rules {
			check(r)
		}
	}
	return refs
}
func removeNode(s *client.ProfileState, id identity.ID) {
	s.Outbounds = slices.DeleteFunc(s.Outbounds, func(o client.Outbound) bool { return o.NodeID != nil && *o.NodeID == id })
	s.Nodes = slices.DeleteFunc(s.Nodes, func(n client.RemoteNode) bool { return n.ID == id })
}
func (s *Service) ApplyManagement(ctx context.Context, r ManagementApply) (ClientResult, error) {
	if s.client == nil {
		return ClientResult{}, identity.Err(identity.NotImplemented, "client runtime unavailable")
	}
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ClientResult{}, identity.Err(identity.Unavailable, "client runtime closed")
	}
	p := c.management.plans[r.Token]
	if p == nil || !p.preview.Applicable || time.Now().After(p.preview.Expires) || r.Revision != p.preview.Revision {
		return ClientResult{}, managementInvalid()
	}
	delete(c.management.plans, r.Token)
	state, e := c.repo.ClientState(ctx)
	if e != nil {
		return ClientResult{}, e
	}
	if state.Revision != r.Revision {
		return ClientResult{}, identity.RevisionConflict(state.Revision)
	}
	return s.commitManagement(ctx, p, state)
}
func (s *Service) commitManagement(ctx context.Context, p *managementPlan, old client.ProfileState) (result ClientResult, err error) {
	c := s.client
	credentials, err := s.clientCredentials(ctx, p.state, p.secrets)
	if err != nil {
		return result, err
	}
	actor, err := localActor()
	if err != nil {
		return result, err
	}
	op, err := c.repo.BeginOperation(ctx, old.Revision, actor)
	if err != nil {
		return result, err
	}
	p.state.Revision = op.TargetRevision
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
	// Metadata, 304 and failure diagnostics do not churn runtime generations.
	runtimeOld, runtimeNew := old.Clone(), p.state.Clone()
	runtimeOld.Revision = 0
	runtimeNew.Revision = 0
	runtimeOld.Management = provider.State{}
	runtimeNew.Management = provider.State{}
	if !reflect.DeepEqual(runtimeOld, runtimeNew) {
		prepared, err = c.manager.Prepare(ctx, p.state, credentials, c.factories)
		if err != nil {
			return result, err
		}
	}
	err = c.repo.CommitOperation(ctx, op, func(w ports.Writer) error {
		cw, ok := w.(ports.ClientWriter)
		if !ok {
			return identity.Err(identity.Unavailable, "client storage unavailable")
		}
		if e := cw.ReplaceClient(p.state, p.secrets); e != nil {
			return e
		}
		pw, ok := w.(ports.ProviderWriter)
		if !ok {
			return identity.Err(identity.Unavailable, "provider storage unavailable")
		}
		return pw.ReplaceProviderSources(p.sources)
	})
	if err != nil {
		return result, err
	}
	committed = true
	if prepared != nil {
		err = prepared.Activate()
		if err != nil {
			c.recoveryError = "host_activation_degraded"
		} else {
			c.recoveryError = ""
		}
	}
	_ = op.Finish(identity.Committed, time.Now(), "")
	return ClientResult{ID: p.preview.ProviderID, Transaction: op}, err
}
