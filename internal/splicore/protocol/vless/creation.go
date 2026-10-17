package vless

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
	var w struct {
		Schema          int             `json:"schema"`
		Name            string          `json:"name"`
		Listener        access.Endpoint `json:"listener"`
		Display         access.Endpoint `json:"display_endpoint"`
		Settings        json.RawMessage `json:"settings"`
		PolicyMode      string          `json:"policy_mode,omitempty"`
		ServerSecret    json.RawMessage `json:"server_secret,omitempty"`
		TransportSecret json.RawMessage `json:"transport_secret,omitempty"`
		Users           []struct {
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
	s, err := decode(w.Settings, false)
	if err != nil {
		return d, err
	}
	if s.Security == Reality && !RealityCompiled {
		return d, identity.Err(identity.NotImplemented, "REALITY requires with_utls")
	}
	var serverSecret struct {
		PrivateKey json.RawMessage `json:"private_key"`
	}
	if len(w.ServerSecret) != 0 && (string(w.ServerSecret) == "null" || creation.Decode(w.ServerSecret, &serverSecret) != nil) {
		return d, invalid()
	}
	if s.Security != Reality && len(w.ServerSecret) != 0 {
		return d, invalid()
	}
	if s.Security == Reality {
		material := ""
		if len(w.ServerSecret) != 0 {
			material, err = creation.RawField(serverSecret.PrivateKey)
			if err != nil {
				return d, invalid()
			}
		}
		p := access.PrivateKeyPayload{Algorithm: "x25519", Material: secret.New(material)}
		if material != "" {
			pub, e := DerivePublicKey(p)
			if e != nil || (s.Reality.PublicKey != "" && s.Reality.PublicKey != pub) {
				return d, invalid()
			}
			s.Reality.PublicKey = pub
		} else if s.Reality.PublicKey != "" {
			return d, invalid()
		}
		d.ServerPayloads = []access.Payload{p}
	}
	if len(w.TransportSecret) != 0 {
		return d, identity.Err(identity.UnsupportedEngineFeature, "transport masks are outside Splicore runtime")
	}
	d.Name = w.Name
	d.Protocol = Key(s.Security)
	d.Transport = "tcp"
	if s.Stream != nil {
		d.Transport = s.Stream.Carrier()
	}
	d.Listener = w.Listener
	d.Display = w.Display
	d.Settings, _ = json.Marshal(s)
	d.TLSVerification = s.Security != Plain
	names, ids := map[string]bool{}, map[string]bool{}
	for _, u := range w.Users {
		id, e := creation.RawField(u.UUID)
		if e != nil || (id != "" && (ValidateUUID(secret.New(id)) != nil || ids[strings.ToLower(id)])) {
			return d, creation.Invalid()
		}
		if err := creation.ValidateUser(u.Name, u.Policy, w.PolicyMode, names); err != nil {
			return d, err
		}
		ids[strings.ToLower(id)] = id != ""
		d.Users = append(d.Users, ports.CreationUser{Name: u.Name, Enabled: creation.Enabled(u.Enabled), AccountEnabled: creation.Enabled(u.AccountEnabled), Payload: access.UUIDPayload{UUID: secret.New(id)}, Policy: u.Policy})
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
	if ValidateUUID(v.UUID) != nil {
		return nil, invalid()
	}
	return v, nil
}
func (Module) MaterializeCreation(d ports.CreationDraft) (ports.CreationDraft, error) {
	s, err := decode(d.Settings, false)
	if err != nil {
		return d, err
	}
	if s.Security != Reality {
		return d, nil
	}
	if len(d.ServerPayloads) != 1 {
		return d, invalid()
	}
	p, ok := d.ServerPayloads[0].(access.PrivateKeyPayload)
	if !ok {
		return d, invalid()
	}
	var pub PublicKey
	if p.Material.Empty() {
		p, pub, err = GenerateServerKey()
	} else {
		pub, err = DerivePublicKey(p)
	}
	if err != nil {
		return d, err
	}
	s.Reality.PublicKey = pub
	d.Settings, _ = json.Marshal(s)
	d.ServerPayloads = []access.Payload{p}
	return d, nil
}
