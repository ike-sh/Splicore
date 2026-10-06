package shadowsocks

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
		ServerKey  json.RawMessage `json:"server_key,omitempty"`
		Users      []struct {
			Name     string             `json:"account_name"`
			Enabled  creation.Flag      `json:"enabled,omitempty"`
			Password json.RawMessage    `json:"password,omitempty"`
			Key      json.RawMessage    `json:"key,omitempty"`
			Policy   *ports.PolicyDraft `json:"traffic_policy,omitempty"`
		} `json:"users"`
	}
	var d ports.CreationDraft
	if creation.Decode(b, &w) != nil || creation.ValidateEnvelope(w.Schema, w.Name, w.Listener, w.Display, w.PolicyMode, len(w.Users)) != nil {
		return d, creation.Invalid()
	}
	s, e := Decode(w.Settings)
	if e != nil {
		return d, e
	}
	m, _ := Lookup(s.Method)
	if m.Edition == "2022" && !s.MultiUser && len(w.Users) != 1 {
		return d, invalid()
	}
	server, e := creation.RawField(w.ServerKey)
	if e != nil || !s.MultiUser && len(w.ServerKey) > 0 {
		return d, invalid()
	}
	if server != "" && ValidateMaterial(s.Method, access.PSKPayload{Key: secret.New(server)}, false) != nil {
		return d, invalid()
	}
	raw, _ := json.Marshal(s)
	d = ports.CreationDraft{Name: w.Name, Protocol: Key(m.Edition), Transport: "tcp", Listener: w.Listener, Display: w.Display, Settings: raw}
	if s.UDP {
		d.AdditionalTransports = []string{"udp"}
	}
	if s.MultiUser {
		d.ServerPayloads = []access.Payload{access.PSKPayload{Key: secret.New(server)}}
	}
	names, keys := map[string]bool{}, map[string]bool{}
	for _, u := range w.Users {
		if e = creation.ValidateUser(u.Name, u.Policy, w.PolicyMode, names); e != nil {
			return d, e
		}
		var p access.Payload
		field := u.Password
		if m.Edition == "2022" {
			if len(u.Password) > 0 {
				return d, invalid()
			}
			field = u.Key
		} else if len(u.Key) > 0 {
			return d, invalid()
		}
		v, e := creation.RawField(field)
		if e != nil {
			return d, e
		}
		if m.Edition == "2022" {
			p = access.PSKPayload{Key: secret.New(v)}
		} else {
			p = access.PasswordPayload{Password: secret.New(v)}
		}
		if v != "" && (ValidateMaterial(s.Method, p, false) != nil || keys[v]) {
			return d, invalid()
		}
		keys[v] = v != ""
		d.Users = append(d.Users, ports.CreationUser{Name: u.Name, Enabled: creation.Enabled(u.Enabled), AccountEnabled: true, Payload: p, Policy: u.Policy})
	}
	return d, nil
}
func (Module) MaterializeCreation(d ports.CreationDraft) (ports.CreationDraft, error) {
	s, e := Decode(d.Settings)
	if e != nil {
		return d, e
	}
	for n, u := range d.Users {
		if Material(u.Payload) == "" {
			p, e := Generate(s.Method)
			if e != nil {
				return d, e
			}
			d.Users[n].Payload = p
		}
	}
	for n, p := range d.ServerPayloads {
		if Material(p) == "" {
			p, e := Generate(s.Method)
			if e != nil {
				return d, e
			}
			d.ServerPayloads[n] = p
		}
	}
	return d, nil
}
func (Module) GenerateCreationCredential(p access.Payload) (access.Payload, error) {
	if access.ValidatePayload(p) != nil {
		return nil, invalid()
	}
	return p, nil // method-aware generation is completed by MaterializeCreation
}
