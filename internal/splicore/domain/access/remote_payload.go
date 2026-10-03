package access

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
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
	case UUIDPassword:
		var pair struct {
			UUID     string `json:"uuid"`
			Password string `json:"password"`
		}
		if len(value) > 16384 || jsonstrict.Decode([]byte(value), &pair) != nil {
			return nil, identity.Err(identity.Invalid, "invalid credential pair")
		}
		p = UUIDPasswordPayload{UUID: secret.New(pair.UUID), Password: secret.New(pair.Password)}
	case UsernamePassword:
		var pair struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if len(value) > 16384 || jsonstrict.Decode([]byte(value), &pair) != nil {
			return nil, identity.Err(identity.Invalid, "invalid credential pair")
		}
		p = UsernamePasswordPayload{Username: secret.New(pair.Username), Password: secret.New(pair.Password)}
	default:
		return nil, identity.Err(identity.Invalid, "remote credential kind unavailable")
	}
	if err := ValidatePayload(p); err != nil {
		return nil, err
	}
	return p, nil
}
