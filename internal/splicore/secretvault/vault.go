// Package secretvault implements injected AES-256-GCM storage encryption.
package secretvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
)

type Vault struct {
	keyID string
	aead  cipher.AEAD
}

var _ ports.Cipher = (*Vault)(nil)

func New(keyID string, key []byte) (*Vault, error) {
	if len(key) != 32 || !identity.Label(keyID, 64) {
		return nil, identity.Err(identity.Invalid, "invalid encryption key configuration")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, identity.Err(identity.Invalid, "invalid encryption key")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, identity.Err(identity.Unavailable, "encryption unavailable")
	}
	return &Vault{keyID, aead}, nil
}
func (v *Vault) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte(secret.Redacted)) }
func (v *Vault) KeyID() string                 { return v.keyID }
func (v *Vault) Seal(plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, identity.Err(identity.Unavailable, "encryption entropy unavailable")
	}
	return v.aead.Seal(nonce, nonce, plain, aad), nil
}

func (v *Vault) Open(data, aad []byte) ([]byte, error) {
	n := v.aead.NonceSize()
	if len(data) < n {
		return nil, identity.Err(identity.Corrupt, "credential decryption failed")
	}
	plain, err := v.aead.Open(nil, data[:n], data[n:], aad)
	if err != nil {
		return nil, identity.Err(identity.Corrupt, "credential decryption failed")
	}
	return plain, nil
}
