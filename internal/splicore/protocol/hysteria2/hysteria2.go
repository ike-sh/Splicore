// Package hysteria2 owns the bounded managed profile, never QUIC/TLS wire code.
package hysteria2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Module struct{}
type TLSSettings struct {
	ServerName      string `json:"server_name"`
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
	CACertificate   string `json:"ca_certificate"`
}

func (TLSSettings) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte("TLSSettings{[REDACTED]}")) }

type Settings struct {
	TLS TLSSettings `json:"tls"`
}

func (Settings) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("Hysteria2Settings{[REDACTED]}"))
}
func Key() access.ProtocolKey {
	return access.ProtocolKey{Protocol: "hysteria2", WireVersion: "2", FeatureProfile: "base"}
}
func invalid() error {
	return identity.Err(identity.Invalid, "unsupported Hysteria2 settings or credential")
}
func absolute(s string) bool {
	return len(s) <= 1024 && !strings.ContainsAny(s, "\x00\r\n") && (strings.HasPrefix(s, "/") || len(s) > 2 && s[1] == ':' && (s[2] == '/' || s[2] == '\\'))
}
func Decode(b []byte) (Settings, error) {
	var s Settings
	if len(b) > 16384 || jsonstrict.Decode(b, &s) != nil {
		return s, invalid()
	}
	kind, err := access.ParseHost(s.TLS.ServerName)
	if err != nil || kind != access.DNS || !absolute(s.TLS.CertificateFile) || !absolute(s.TLS.PrivateKeyFile) || len(s.TLS.CACertificate) > 8192 {
		return s, invalid()
	}
	if _, err = CAPool(s.TLS.CACertificate); err != nil {
		return s, err
	}
	return s, nil
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
func (Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Key: Key(), ABI: 1, CredentialKinds: []access.CredentialKind{access.Password}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "sing-box v1.14.1 / sing-quic v0.7.0; password identity; static TLS; no obfs"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{
		Transport: ports.TransportCapabilities{TCP: true, UDPTransport: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true},
		Identity:  ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; runtime generation"},
		Security:  ports.SecurityCapabilities{TLS: true}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported},
		Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable},
		Clients:  []ports.ClientCompatibility{{Format: ports.Mihomo, Client: "mihomo", Version: "1.19.30", Evidence: "docs/reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md"}, {Format: ports.SingBox, Client: "sing-box", Version: "1.14.1", Evidence: "docs/reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md"}},
	}
}
func (Module) ValidateInbound(i access.Inbound) error {
	if err := i.Validate(); err != nil {
		return err
	}
	if _, err := Decode(i.Settings.Data); err != nil {
		return err
	}
	if i.Protocol != Key() || i.Engine != "native" || !i.Enabled || len(i.Listeners) != 1 || i.Listeners[0].Transport != "udp" || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	return nil
}
func (Module) ValidateCredential(c access.Credential) error {
	p, ok := c.Payload.(access.PasswordPayload)
	if c.Validate() != nil || c.Kind != access.Password || c.State != "active" || !ok {
		return invalid()
	}
	return ValidatePassword(p.Password)
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if err := m.ValidateInbound(in.Inbound); err != nil {
		return in, err
	}
	if len(in.Bindings) != len(in.Credentials) || len(in.Bindings) > 16 {
		return in, invalid()
	}
	ids, passwords := map[identity.ID]bool{}, map[string]bool{}
	for n, b := range in.Bindings {
		c := in.Credentials[n]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil {
			return in, invalid()
		}
		ids[b.ID] = true
		key := c.Payload.(access.PasswordPayload).Password.Reveal()
		if passwords[key] {
			return in, invalid()
		}
		passwords[key] = true
	}
	return in, nil
}
func (m Module) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, err := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}}); err != nil {
		return clientprofile.Profile{}, err
	}
	s, _ := Decode(b.Inbound.Settings.Data)
	options, _ := json.Marshal(struct{}{})
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, TLS: clientprofile.TLS{Enabled: true, ServerName: s.TLS.ServerName, ALPN: []string{"h3"}, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}, Transport: clientprofile.Transport{Kind: "quic"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: options}, Metadata: identity.Metadata{}}
	return p, p.Validate()
}
