package amneziawgendpoint

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
)

// GenerateKeys uses the official private-key parser/clamping representation.
// Returning the private key is intentional only for explicit key generation.
func GenerateKeys() (string, string, error) {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", "", err
	}
	var key device.NoisePrivateKey
	if err := key.FromHex(hex.EncodeToString(entropy[:])); err != nil {
		return "", "", err
	}
	private, err := ecdh.X25519().NewPrivateKey(key[:])
	if err != nil {
		return "", "", err
	}
	var public [32]byte
	copy(public[:], private.PublicKey().Bytes())
	return E.EncodeKey([32]byte(key)), E.EncodeKey(public), nil
}
