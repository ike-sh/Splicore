package trojan

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
	"github.com/ike-sh/Splicore/protocol/trojan/wire"
)

func (Module) DecodeCreation(b json.RawMessage) (ports.CreationDraft, error) {
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
			Password       json.RawMessage    `json:"password"`
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
	raw, _ := json.Marshal(s)
	d = ports.CreationDraft{Name: w.Name, Protocol: Key(), Transport: "tcp", Listener: w.Listener, Display: w.Display, Settings: raw, TLSVerification: true}
	if s.Stream != nil {
		d.Transport = s.Stream.Carrier()
	}
	names, keys := map[string]bool{}, map[wire.Key]bool{}
	for _, u := range w.Users {
		pass, err := creation.RawField(u.Password)
		if err != nil || creation.ValidateUser(u.Name, u.Policy, w.PolicyMode, names) != nil {
			return d, creation.Invalid()
		}
		v := secret.New(pass)
		if pass != "" {
			key := wire.Derive(v)
			if credential.ValidatePassword(v) != nil || keys[key] {
				return d, creation.Invalid()
			}
			keys[key] = true
		}
		d.Users = append(d.Users, ports.CreationUser{Name: u.Name, Enabled: creation.Enabled(u.Enabled), AccountEnabled: creation.Enabled(u.AccountEnabled), Payload: access.PasswordPayload{Password: v}, Policy: u.Policy})
	}
	return d, nil
}
func (Module) GenerateCreationCredential(p access.Payload) (access.Payload, error) {
	v, ok := p.(access.PasswordPayload)
	if !ok {
		return nil, invalid()
	}
	if v.Password.Empty() {
		var err error
		v.Password, err = credential.GeneratePassword()
		return v, err
	}
	return v, nil
}
