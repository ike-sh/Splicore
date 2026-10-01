// Package credential supplies shared managed credential rules and generation.
package credential

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"unicode"
	"unicode/utf8"
)

func invalid() error { return identity.Err(identity.Invalid, "invalid managed password") }
func ValidatePassword(v secret.Value) error {
	s := v.Reveal()
	if len(s) < 12 || len(s) > 255 || !utf8.ValidString(s) {
		return invalid()
	}
	for _, c := range s {
		if unicode.IsControl(c) || unicode.IsSpace(c) {
			return invalid()
		}
	}
	return nil
}
func GeneratePassword() (secret.Value, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return secret.Value{}, identity.Err(identity.Unavailable, "credential entropy unavailable")
	}
	return secret.New(base64.RawURLEncoding.EncodeToString(b[:])), nil
}
