package access

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
)

// DecodeRemotePayload is a generic, explicit credential write boundary. The
// selected protocol adapter validates its own accepted kind and portable profile.
func DecodeRemotePayload(kind CredentialKind, value string) (Payload, error) {
	var p Payload
	switch kind {
	case PSK:
		p = PSKPayload{Key: secret.New(value)}
	case Password:
		p = PasswordPayload{Password: secret.New(value)}
	case UUID:
		p = UUIDPayload{UUID: secret.New(value)}
	default:
		return nil, identity.Err(identity.Invalid, "remote credential kind unavailable")
	}
	if err := ValidatePayload(p); err != nil {
		return nil, err
	}
	return p, nil
}
