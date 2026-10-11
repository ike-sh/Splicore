package anytls

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

func (Module) DecodeCreation(b json.RawMessage) (ports.CreationDraft, error) {
	var doc struct {
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
	var draft ports.CreationDraft
	if creation.Decode(b, &doc) != nil || creation.ValidateEnvelope(doc.Schema, doc.Name, doc.Listener, doc.Display, doc.PolicyMode, len(doc.Users)) != nil {
		return draft, creation.Invalid()
	}
	settings, err := Decode(doc.Settings)
	if err != nil {
		return draft, err
	}
	data, _ := json.Marshal(settings)
	draft = ports.CreationDraft{Name: doc.Name, Protocol: Key(), Transport: "tcp", Listener: doc.Listener, Display: doc.Display, Settings: data, TLSVerification: true}
	names, keys := map[string]bool{}, map[wire.AuthKey]bool{}
	for _, user := range doc.Users {
		password, err := creation.RawField(user.Password)
		if err != nil || creation.ValidateUser(user.Name, user.Policy, doc.PolicyMode, names) != nil {
			return draft, creation.Invalid()
		}
		value := secret.New(password)
		if password != "" {
			key := wire.PasswordKey(password)
			if credential.ValidatePassword(value) != nil || keys[key] {
				return draft, creation.Invalid()
			}
			keys[key] = true
		}
		draft.Users = append(draft.Users, ports.CreationUser{Name: user.Name, Enabled: creation.Enabled(user.Enabled), AccountEnabled: creation.Enabled(user.AccountEnabled), Payload: access.PasswordPayload{Password: value}, Policy: user.Policy})
	}
	return draft, nil
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
