package mieru

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
)

func (Module) DecodeCreation(data json.RawMessage) (ports.CreationDraft, error) {
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
			Username json.RawMessage    `json:"username"`
			Password json.RawMessage    `json:"password"`
			Policy   *ports.PolicyDraft `json:"traffic_policy,omitempty"`
		} `json:"users"`
	}
	var d ports.CreationDraft
	if creation.Decode(data, &w) != nil || creation.ValidateEnvelope(w.Schema, w.Name, w.Listener, w.Display, w.PolicyMode, len(w.Users)) != nil {
		return d, creation.Invalid()
	}
	s, e := Decode(w.Settings)
	if e != nil {
		return d, e
	}
	raw, _ := json.Marshal(s)
	d = ports.CreationDraft{Name: w.Name, Protocol: Key(), Transport: s.Transport, Listener: w.Listener, Display: w.Display, Settings: raw}
	names, usernames := map[string]bool{}, map[string]bool{}
	for _, u := range w.Users {
		name, e := creation.RawField(u.Username)
		if e != nil {
			return d, creation.Invalid()
		}
		password, e := creation.RawField(u.Password)
		if e != nil {
			return d, creation.Invalid()
		}
		if e = creation.ValidateUser(u.Name, u.Policy, w.PolicyMode, names); e != nil {
			return d, e
		}
		if (name == "") != (password == "") || name != "" && (ValidateUsername(secret.New(name)) != nil || ValidatePassword(secret.New(password)) != nil || usernames[name]) {
			return d, creation.Invalid()
		}
		usernames[name] = name != ""
		d.Users = append(d.Users, ports.CreationUser{Name: u.Name, Enabled: creation.Enabled(u.Enabled), AccountEnabled: true, Payload: access.UsernamePasswordPayload{Username: secret.New(name), Password: secret.New(password)}, Policy: u.Policy})
	}
	return d, nil
}
func (Module) GenerateCreationCredential(p access.Payload) (access.Payload, error) {
	v, ok := p.(access.UsernamePasswordPayload)
	if !ok {
		return nil, invalid()
	}
	if v.Password.Empty() && v.Username.Empty() {
		name, e := credential.GeneratePassword()
		if e != nil {
			return nil, e
		}
		password, e := credential.GeneratePassword()
		if e != nil {
			return nil, e
		}
		v.Username = secret.New("u-" + name.Reveal()[:20])
		v.Password = password
	}
	if ValidateUsername(v.Username) != nil || ValidatePassword(v.Password) != nil {
		return nil, invalid()
	}
	return v, nil
}
