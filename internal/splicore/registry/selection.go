package registry

import (
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"slices"
)

func (p *Protocols) DecodeCreation(engines *Engines, protocol string, b json.RawMessage) (ports.CreationDraft, error) {
	codec, err := p.Creation(protocol)
	if err != nil {
		return ports.CreationDraft{}, err
	}
	var envelope map[string]json.RawMessage
	if len(b) > 65536 || jsonstrict.Decode(b, &envelope) != nil || envelope == nil {
		return ports.CreationDraft{}, identity.Err(identity.Invalid, "invalid creation document")
	}
	engine := "native"
	if raw, ok := envelope["engine"]; ok {
		if string(raw) == "null" || json.Unmarshal(raw, &engine) != nil || !identity.Label(engine, 64) {
			return ports.CreationDraft{}, identity.Err(identity.Invalid, "invalid engine selection")
		}
		delete(envelope, "engine")
	}
	command, _ := json.Marshal(envelope)
	d, err := codec.DecodeCreation(command)
	if err != nil {
		return d, err
	}
	if d.Protocol.Protocol != protocol {
		return d, identity.Err(identity.Invalid, "creation identity mismatch")
	}
	_, err = p.Get(d.Protocol)
	if err != nil {
		return d, err
	}
	eng, err := engines.Get(engine)
	if err != nil {
		return d, identity.Err(identity.UnsupportedEngineForProtocol, "UnsupportedEngineForProtocol")
	}
	m := eng.Metadata()
	if !slices.Contains(m.Protocols, protocol) {
		return d, identity.Err(identity.UnsupportedEngineForProtocol, "UnsupportedEngineForProtocol")
	}
	if m.Availability != ports.Compiled || !m.RuntimeImplemented {
		return d, identity.Err(identity.NotImplemented, "selected engine implementation unavailable")
	}
	d.Engine = engine
	return d, err
}
