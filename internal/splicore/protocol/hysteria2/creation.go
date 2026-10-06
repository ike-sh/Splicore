package hysteria2

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
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
			Name     string             `json:"account_name"`
			Enabled  creation.Flag      `json:"enabled,omitempty"`
			Password json.RawMessage    `json:"password"`
			Policy   *ports.PolicyDraft `json:"traffic_policy,omitempty"`
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
	d = ports.CreationDraft{Name: w.Name, Protocol: Key(), Transport: "udp", Listener: w.Listener, Display: w.Display, Settings: raw, TLSVerification: true}
	names, passwords := map[string]bool{}, map[string]bool{}
	for _, u := range w.Users {
		p, err := creation.RawField(u.Password)
		if err != nil || creation.ValidateUser(u.Name, u.Policy, w.PolicyMode, names) != nil {
			return d, creation.Invalid()
		}
		if p != "" && (ValidatePassword(secret.New(p)) != nil || passwords[p]) {
			return d, creation.Invalid()
		}
		passwords[p] = p != ""
		d.Users = append(d.Users, ports.CreationUser{Name: u.Name, Enabled: creation.Enabled(u.Enabled), AccountEnabled: true, Payload: access.PasswordPayload{Password: secret.New(p)}, Policy: u.Policy})
	}
	return d, nil
}
func (Module) GenerateCreationCredential(p access.Payload) (access.Payload, error) {
	v := p.(access.PasswordPayload)
	if v.Password.Empty() {
		pass, err := GeneratePassword()
		v.Password = pass
		return v, err
	}
	return v, nil
}
