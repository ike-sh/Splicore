package vmess

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
	"strings"
)

func (Module) DecodeCreation(b json.RawMessage) (ports.CreationDraft, error) {
	canonical, err := creationJSON(b)
	if err != nil {
		return ports.CreationDraft{}, err
	}
	b = canonical
	var w struct {
		Schema     int             `json:"schema"`
		Name       string          `json:"name"`
		Listener   access.Endpoint `json:"listener"`
		Display    access.Endpoint `json:"display_endpoint"`
		Settings   json.RawMessage `json:"settings"`
		PolicyMode string          `json:"policy_mode,omitempty"`
		Users      []struct {
			Name           string             `json:"account_name"`
			Enabled        creation.Flag      `json:"enabled,omitempty"`
			AccountEnabled creation.Flag      `json:"account_enabled,omitempty"`
			UUID           json.RawMessage    `json:"uuid,omitempty"`
			Policy         *ports.PolicyDraft `json:"traffic_policy,omitempty"`
		} `json:"users"`
	}
	var d ports.CreationDraft
	if creation.Decode(b, &w) != nil || creation.ValidateEnvelope(w.Schema, w.Name, w.Listener, w.Display, w.PolicyMode, len(w.Users)) != nil {
		return d, creation.Invalid()
	}
	s, err := Decode(w.Settings)
	if err != nil {
		return d, err
	}
	d = ports.CreationDraft{Name: w.Name, Protocol: Key(), Transport: "tcp", Listener: w.Listener, Display: w.Display, TLSVerification: s.Security == "tls"}
	d.Settings, _ = json.Marshal(s)
	names, ids := map[string]bool{}, map[string]bool{}
	for _, u := range w.Users {
		id, err := creation.RawField(u.UUID)
		p := access.UUIDPayload{UUID: secret.New(id)}
		if err != nil || id != "" && (p.Validate() != nil || ids[strings.ToLower(id)]) || creation.ValidateUser(u.Name, u.Policy, w.PolicyMode, names) != nil {
			return d, creation.Invalid()
		}
		if id != "" {
			ids[strings.ToLower(id)] = true
		}
		d.Users = append(d.Users, ports.CreationUser{Name: u.Name, Enabled: creation.Enabled(u.Enabled), AccountEnabled: creation.Enabled(u.AccountEnabled), Payload: p, Policy: u.Policy})
	}
	return d, nil
}
func (Module) GenerateCreationCredential(p access.Payload) (access.Payload, error) {
	v, ok := p.(access.UUIDPayload)
	if !ok {
		return nil, invalid()
	}
	if v.UUID.Empty() {
		id, err := identity.NewID()
		if err != nil {
			return nil, err
		}
		v.UUID = secret.New(string(id))
	}
	return v, v.Validate()
}
