// Package creation validates the shared multi-user creation envelope.
package creation

import (
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"net/netip"
)

// Flag preserves omission and rejects explicit null or non-boolean values.
type Flag struct{ Present, Value bool }

func (f *Flag) UnmarshalJSON(b []byte) error {
	if string(b) == "null" || json.Unmarshal(b, &f.Value) != nil {
		return Invalid()
	}
	f.Present = true
	return nil
}

func ValidateEnvelope(schema int, name string, listener, display access.Endpoint, mode string, count int) error {
	ip, err := netip.ParseAddr(listener.Host)
	if schema != 1 || !identity.Label(name, 128) || listener.Validate() != nil || display.Validate() != nil || err != nil || ip.Zone() != "" || count < 1 || count > 16 || (mode != "" && mode != "metadata_only") {
		return Invalid()
	}
	return nil
}
func Invalid() error { return identity.Err(identity.Invalid, "invalid creation document") }
func Decode(b []byte, v any) error {
	if len(b) > 65536 {
		return Invalid()
	}
	return jsonstrict.Decode(b, v)
}
func ValidateUser(name string, policy *ports.PolicyDraft, mode string, names map[string]bool) error {
	if !identity.Label(name, 128) || names[name] {
		return Invalid()
	}
	names[name] = true
	if policy != nil {
		if mode != "metadata_only" {
			return Invalid()
		}
		for _, n := range []*int64{policy.QuotaBytes, policy.UploadBps, policy.DownloadBps} {
			if n != nil && *n < 0 {
				return Invalid()
			}
		}
	}
	return nil
}
func Enabled(p Flag) bool { return !p.Present || p.Value }

// RawField refuses null/number/object secrets while allowing omitted generation.
func RawField(b json.RawMessage) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	var s string
	if string(b) == "null" || json.Unmarshal(b, &s) != nil || s == "" {
		return "", Invalid()
	}
	return s, nil
}
