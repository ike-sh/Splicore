package registry

import (
	"encoding/json"

	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
)

// CheckCreation uses the production codec and snapshots referenced TLS material
// without creating credentials, sockets, workers or database records.
func (p *Protocols) CheckCreation(engines *Engines, protocol string, document json.RawMessage) error {
	draft, err := p.DecodeCreation(engines, protocol, document)
	if err != nil {
		return err
	}
	return CheckTLSResources(draft.Settings)
}

// CheckTLSResources checks the shared TLS resource contract used by the native
// server codecs. All other protocol/network settings remain codec-owned.
func CheckTLSResources(settings json.RawMessage) error {
	var shared struct {
		TLS *tlsconfig.Settings `json:"tls"`
	}
	if err := json.Unmarshal(settings, &shared); err != nil {
		return err
	}
	if shared.TLS != nil {
		_, key, err := tlsconfig.Snapshot(*shared.TLS)
		clear(key)
		return err
	}
	return nil
}
