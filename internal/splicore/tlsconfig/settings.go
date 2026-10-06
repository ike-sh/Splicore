// Package tlsconfig owns the shared static TLS trust and identity contract.
package tlsconfig

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"strings"
)

func invalid() error { return identity.Err(identity.Invalid, "invalid TLS settings") }

type Settings struct {
	ServerName      string `json:"server_name"`
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
	CACertificate   string `json:"ca_certificate"`
}

func (Settings) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte("Settings{[REDACTED]}")) }

func absolute(s string) bool {
	return len(s) <= 1024 && !strings.ContainsAny(s, "\x00\r\n") && (strings.HasPrefix(s, "/") || len(s) > 2 && s[1] == ':' && (s[2] == '/' || s[2] == '\\'))
}
func Validate(s Settings) error {
	kind, err := access.ParseHost(s.ServerName)
	if err != nil || kind != access.DNS || !absolute(s.CertificateFile) || !absolute(s.PrivateKeyFile) || len(s.CACertificate) > 8192 {
		return invalid()
	}
	_, err = CAPool(s.CACertificate)
	return err
}
func CAPool(value string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := []byte(value)
	n := 0
	for len(strings.TrimSpace(string(rest))) > 0 {
		if !strings.HasPrefix(strings.TrimSpace(string(rest)), "-----BEGIN CERTIFICATE-----") {
			return nil, invalid()
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, invalid()
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return nil, invalid()
		}
		pool.AddCert(cert)
		rest = next
		n++
	}
	if n != 1 {
		return nil, invalid()
	}
	return pool, nil
}

// CAFingerprint identifies the sole explicit trust anchor, never the leaf.
// Mihomo v1.19.30 verifies the leaf chain and SNI when a non-leaf pin matches.
func CAFingerprint(value string) (string, error) {
	if _, err := CAPool(value); err != nil {
		return "", err
	}
	block, _ := pem.Decode([]byte(value))
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
