package access

import (
	"crypto/x509"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

// ClientTLS contains only public client trust material. It cannot represent a
// server certificate key or REALITY private key.
type ClientTLS struct {
	Enabled          bool     `json:"enabled"`
	ServerName       string   `json:"server_name,omitempty"`
	ALPN             []string `json:"alpn,omitempty"`
	Trust            string   `json:"trust,omitempty"`
	CACertificate    string   `json:"ca_certificate,omitempty"`
	RealityPublicKey string   `json:"reality_public_key,omitempty"`
	RealityShortID   string   `json:"reality_short_id,omitempty"`
}

func (t ClientTLS) Validate(kind string) error {
	bad := func() error { return identity.Err(identity.Invalid, "invalid public client security settings") }
	if kind == "none" {
		if t.Enabled || t.ServerName != "" || len(t.ALPN) != 0 || t.Trust != "" || t.CACertificate != "" || t.RealityPublicKey != "" || t.RealityShortID != "" {
			return bad()
		}
		return nil
	}
	if !t.Enabled || !identity.Label(t.ServerName, 253) || len(t.ALPN) > 8 {
		return bad()
	}
	for _, a := range t.ALPN {
		if !identity.Label(a, 255) {
			return bad()
		}
	}
	if kind == "reality" {
		if (t.Trust != "" && t.Trust != "reality") || t.CACertificate != "" || len(t.RealityPublicKey) > 64 || len(t.RealityShortID) > 16 {
			return bad()
		}
		return nil
	}
	if kind != "tls" || t.RealityPublicKey != "" || t.RealityShortID != "" {
		return bad()
	}
	if t.Trust == "system" && t.CACertificate == "" {
		return nil
	}
	if t.Trust != "explicit_ca" || len(t.CACertificate) > 65536 || !x509.NewCertPool().AppendCertsFromPEM([]byte(t.CACertificate)) {
		return bad()
	}
	return nil
}
