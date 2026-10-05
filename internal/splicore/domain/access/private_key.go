package access

import (
	"encoding/base64"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
)

// PrivateKeyPayload is server key material, separate from client authentication.
// The algorithm is bounded; protocol adapters own derivation and usage.
type PrivateKeyPayload struct {
	Algorithm string
	Material  secret.Value
}

func (PrivateKeyPayload) Kind() CredentialKind { return PrivateKey }
func (PrivateKeyPayload) credentialPayload()   {}
func (p PrivateKeyPayload) Validate() error {
	b, err := base64.RawURLEncoding.Strict().DecodeString(p.Material.Reveal())
	defer clear(b)
	if p.Algorithm != "x25519" || err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != p.Material.Reveal() {
		return identity.Err(identity.Invalid, "invalid server key material")
	}
	return nil
}
