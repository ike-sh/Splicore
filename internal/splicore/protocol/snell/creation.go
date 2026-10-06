package snell

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"net/netip"
)

type Document struct {
	Schema            int
	AccountName, Name string
	Listener, Display access.Endpoint
	Settings          Settings
	PSK               secret.Value
}

func DecodeSnell(b []byte) (Document, error) {
	var w struct {
		Schema      int             `json:"schema"`
		AccountName string          `json:"account_name"`
		Name        string          `json:"name"`
		Listener    access.Endpoint `json:"listener"`
		Display     access.Endpoint `json:"display_endpoint"`
		Settings    json.RawMessage `json:"settings"`
		PSK         json.RawMessage `json:"psk"`
	}
	if e := jsonstrict.Decode(b, &w); e != nil {
		return Document{}, e
	}
	settings, e := Decode(w.Settings)
	if e != nil {
		return Document{}, e
	}
	var supplied string
	if len(w.PSK) > 0 {
		if json.Unmarshal(w.PSK, &supplied) != nil || ValidatePSK(secret.New(supplied)) != nil {
			return Document{}, identity.Err(identity.Invalid, "invalid supplied Snell PSK")
		}
	}
	d := Document{w.Schema, w.AccountName, w.Name, w.Listener, w.Display, settings, secret.New(supplied)}
	if ip, err := netip.ParseAddr(d.Listener.Host); err != nil || ip.Zone() != "" {
		return Document{}, identity.Err(identity.Invalid, "listener requires an IP address")
	}
	if d.Schema != 1 || !identity.Label(d.Name, 128) || !identity.Label(d.AccountName, 128) || d.Listener.Validate() != nil || d.Display.Validate() != nil {
		return Document{}, identity.Err(identity.Invalid, "invalid Snell document")
	}
	if !d.PSK.Empty() {
		if e = ValidatePSK(d.PSK); e != nil {
			return Document{}, e
		}
	}
	return d, nil
}

func (Module) DecodeCreation(b json.RawMessage) (ports.CreationDraft, error) {
	d, err := DecodeSnell(b)
	if err != nil {
		return ports.CreationDraft{}, err
	}
	raw, _ := json.Marshal(d.Settings)
	return ports.CreationDraft{Name: d.Name, Protocol: Key(d.Settings.Version), Transport: "tcp", Listener: d.Listener, Display: d.Display, Settings: raw, Users: []ports.CreationUser{{Name: d.AccountName, Enabled: true, AccountEnabled: true, Payload: access.PSKPayload{Key: d.PSK}}}}, nil
}
func (Module) GenerateCreationCredential(p access.Payload) (access.Payload, error) {
	v := p.(access.PSKPayload)
	if v.Key.Empty() {
		pass, err := GeneratePSK()
		v.Key = pass
		return v, err
	}
	return v, nil
}
