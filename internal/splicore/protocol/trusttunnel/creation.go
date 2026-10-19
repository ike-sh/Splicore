package trusttunnel

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
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
			Username       string             `json:"username"`
			Password       json.RawMessage    `json:"password"`
			Enabled        creation.Flag      `json:"enabled,omitempty"`
			AccountEnabled creation.Flag      `json:"account_enabled,omitempty"`
			Policy         *ports.PolicyDraft `json:"traffic_policy,omitempty"`
		} `json:"users"`
	}
	var draft ports.CreationDraft
	if creation.Decode(b, &w) != nil || creation.ValidateEnvelope(w.Schema, w.Name, w.Listener, w.Display, w.PolicyMode, len(w.Users)) != nil {
		return draft, creation.Invalid()
	}
	s, err := Decode(w.Settings)
	if err != nil {
		return draft, err
	}
	raw, _ := json.Marshal(s)
	transport := "tcp"
	if s.Mode == "http3" {
		transport = "udp"
	}
	draft = ports.CreationDraft{Name: w.Name, Protocol: Key(), Transport: transport, Listener: w.Listener, Display: w.Display, Settings: raw, TLSVerification: true}
	if s.Mode == "auto" {
		draft.AdditionalTransports = []string{"udp"}
	}
	names, users := map[string]bool{}, map[string]bool{}
	for _, user := range w.Users {
		pass, err := creation.RawField(user.Password)
		if err != nil || user.Username == "" || len(user.Username) > 255 || strings.ContainsAny(user.Username, ":\x00\r\n") || users[user.Username] {
			return draft, creation.Invalid()
		}
		if err := creation.ValidateUser(user.Name, user.Policy, w.PolicyMode, names); err != nil {
			return draft, err
		}
		payload := access.UsernamePasswordPayload{Username: secret.New(user.Username), Password: secret.New(pass)}
		if pass != "" {
			if _, err = (Module{}).GenerateCreationCredential(payload); err != nil {
				return draft, err
			}
		}
		users[user.Username] = true
		draft.Users = append(draft.Users, ports.CreationUser{Name: user.Name, Enabled: creation.Enabled(user.Enabled), AccountEnabled: creation.Enabled(user.AccountEnabled), Payload: payload, Policy: user.Policy})
	}
	return draft, nil
}
func (Module) GenerateCreationCredential(payload access.Payload) (access.Payload, error) {
	pair, ok := payload.(access.UsernamePasswordPayload)
	if !ok {
		return nil, invalid()
	}
	if pair.Password.Empty() {
		pass, err := credential.GeneratePassword()
		if err != nil {
			return nil, err
		}
		pair.Password = pass
	}
	// Reuse the generic proxy credential validation without ownership metadata.
	if _, err := proxy.Pair(access.Credential{Payload: pair}); err != nil {
		return nil, invalid()
	}
	return pair, nil
}
