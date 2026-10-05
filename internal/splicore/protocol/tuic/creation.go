package tuic

import (
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/credential"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/protocol/creation"
	"strings"
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
			UUID           json.RawMessage    `json:"uuid"`
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
	d = ports.CreationDraft{Name: w.Name, Protocol: Key(), Transport: "udp", Listener: w.Listener, Display: w.Display, Settings: raw, TLSVerification: true}
	names, uuids := map[string]bool{}, map[string]bool{}
	for _, u := range w.Users {
		id, e1 := creation.RawField(u.UUID)
		pass, e2 := creation.RawField(u.Password)
		if e1 != nil || e2 != nil || (id == "") != (pass == "") || creation.ValidateUser(u.Name, u.Policy, w.PolicyMode, names) != nil {
			return d, creation.Invalid()
		}
		if id != "" && (ValidateUUID(secret.New(id)) != nil || credential.ValidatePassword(secret.New(pass)) != nil || uuids[strings.ToLower(id)]) {
			return d, creation.Invalid()
		}
		uuids[strings.ToLower(id)] = id != ""
		d.Users = append(d.Users, ports.CreationUser{Name: u.Name, Enabled: creation.Enabled(u.Enabled), AccountEnabled: creation.Enabled(u.AccountEnabled), Payload: access.UUIDPasswordPayload{UUID: secret.New(id), Password: secret.New(pass)}, Policy: u.Policy})
	}
	return d, nil
}
func (Module) GenerateCreationCredential(p access.Payload) (access.Payload, error) {
	v := p.(access.UUIDPasswordPayload)
	if v.UUID.Empty() {
		return GenerateCredential()
	}
	return v, nil
}
