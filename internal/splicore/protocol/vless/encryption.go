package vless

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

// EncryptionConfig is the sole adapter from canonical public options to wire
// configuration. Historical omitted fields retain plain VLESS semantics.
func EncryptionConfig(s string) (*encryption.Config, error) {
	c, e := encryption.ParseClient(encryptionValue(s))
	if e != nil {
		return nil, invalid()
	}
	return c, nil
}

// DecryptionConfig verifies that the inbound secret and public projection agree.
// It never returns the secret string through generic inbound/profile serializers.
func DecryptionConfig(s Settings, credentials []access.Credential) (*encryption.Config, error) {
	var result *encryption.Config
	for _, credential := range credentials {
		p, ok := credential.Payload.(access.PrivateKeyPayload)
		if !ok {
			return nil, invalid()
		}
		if p.Algorithm != "vless-encryption" {
			continue
		}
		if result != nil || credential.Validate() != nil || credential.State != "active" {
			return nil, invalid()
		}
		var e error
		result, e = encryption.ParseServer(p.Material.Reveal())
		if e != nil || result == nil {
			return nil, invalid()
		}
		if result.ClientString(true) != s.Encryption {
			return nil, invalid()
		}
	}
	if (result != nil) != (s.Encryption != "" && s.Encryption != "none") {
		return nil, invalid()
	}
	return result, nil
}
