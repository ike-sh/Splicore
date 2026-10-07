// Package vmess owns the managed modern VMess AEAD compatibility boundary.
package vmess

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/protocol/vmess/wire"
)

type Module struct{}

func Key() access.ProtocolKey {
	return access.ProtocolKey{Protocol: "vmess", WireVersion: "aead", FeatureProfile: "base"}
}
func invalid() error {
	return identity.Err(identity.Invalid, "invalid modern VMess settings or credential")
}
func Unsupported(code string) error { return reasonError(identity.UnsupportedExport, code) }

type Settings struct {
	Transport       string              `json:"transport"`
	Security        string              `json:"security"`
	PayloadSecurity string              `json:"payload_security"`
	AlterID         int                 `json:"alter_id"`
	TLS             *tlsconfig.Settings `json:"tls,omitempty"`
	ALPN            []string            `json:"alpn,omitempty"`
}

func (Settings) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("VMessSettings{[REDACTED]}")) }
func Security(name string) (byte, error) {
	switch name {
	case "auto":
		switch runtime.GOARCH {
		case "amd64", "arm64", "s390x":
			return wire.AESGCM, nil
		default:
			return wire.ChaCha, nil
		}
	case "aes-128-gcm":
		return wire.AESGCM, nil
	case "chacha20-poly1305":
		return wire.ChaCha, nil
	case "none":
		return wire.None, nil
	default:
		return 0, Unsupported("unsupported_security")
	}
}
func ResolvedSecurity(name string) string {
	v, err := Security(name)
	if err != nil {
		return "unsupported"
	}
	switch v {
	case wire.AESGCM:
		return "aes-128-gcm"
	case wire.ChaCha:
		return "chacha20-poly1305"
	default:
		return "none"
	}
}
func noNull(b []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil {
		return false
	}
	for _, v := range fields {
		if strings.TrimSpace(string(v)) == "null" {
			return false
		}
	}
	return true
}
func Decode(b []byte) (Settings, error) {
	var s Settings
	var err error
	b, err = managedJSON(b, []string{"transport", "security", "payload_security", "alter_id", "tls", "alpn"})
	if err != nil {
		return s, err
	}
	if len(b) > 16384 || jsonstrict.Decode(b, &s) != nil || !noNull(b) {
		return s, invalid()
	}
	if s.Transport == "" {
		s.Transport = "tcp"
	}
	if s.Security == "" {
		s.Security = "none"
	}
	if s.PayloadSecurity == "" {
		s.PayloadSecurity = "auto"
	}
	if s.AlterID != 0 {
		return s, Unsupported("unsupported_legacy_vmess")
	}
	if s.Transport != "tcp" {
		return s, Unsupported("unsupported_transport")
	}
	if _, err := Security(s.PayloadSecurity); err != nil {
		return s, err
	}
	switch s.Security {
	case "none":
		if s.TLS != nil || len(s.ALPN) > 0 {
			return s, invalid()
		}
	case "tls":
		if s.TLS == nil || tlsconfig.Validate(*s.TLS) != nil {
			return s, invalid()
		}
		v := access.ClientTLS{Enabled: true, ServerName: s.TLS.ServerName, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate, ALPN: s.ALPN}
		if v.Validate("tls") != nil {
			return s, invalid()
		}
	default:
		return s, Unsupported("unsupported_transport")
	}
	return s, nil
}

type ClientOptions struct {
	Security string `json:"security"`
	AlterID  int    `json:"alter_id"`
	UDP      bool   `json:"udp"`
}

func DecodeClientOptions(b []byte) (ClientOptions, error) {
	var err error
	b, err = managedJSON(b, []string{"security", "alter_id", "udp"})
	if err != nil {
		return ClientOptions{}, err
	}
	var v struct {
		Security string        `json:"security"`
		AlterID  int           `json:"alter_id"`
		UDP      creation.Flag `json:"udp"`
	}
	if len(b) > 16384 || jsonstrict.Decode(b, &v) != nil || !noNull(b) {
		return ClientOptions{}, invalid()
	}
	if v.Security == "" {
		v.Security = "auto"
	}
	if v.AlterID != 0 {
		return ClientOptions{}, Unsupported("unsupported_legacy_vmess")
	}
	if _, err := Security(v.Security); err != nil {
		return ClientOptions{}, err
	}
	return ClientOptions{Security: v.Security, UDP: creation.Enabled(v.UDP)}, nil
}
func CommandKey(p access.UUIDPayload) wire.Key {
	id, _ := uuid.FromString(p.UUID.Reveal())
	return wire.CommandKey([16]byte(id))
}
func (Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Roles: ports.Roles{Inbound: true, Outbound: true}, Key: Key(), ABI: 1, CredentialKinds: []access.CredentialKind{access.UUID}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "Splicore-owned modern VMess AEAD; alterId=0; TCP/standard bound UDP; raw TCP/shared TLS; legacy/mux/extensions deferred"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{Transport: ports.TransportCapabilities{Kinds: []string{"tcp"}, TCP: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Identity: ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; runtime generation"}, Security: ports.SecurityCapabilities{TLS: true}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}, Clients: []ports.ClientCompatibility{{Format: ports.SingBox, Client: "sing-box", Version: "1.14.2", Evidence: "docs/reports/PHASE19_NATIVE_VMESS_IMPLEMENTATION_REPORT.md"}, {Format: ports.Mihomo, Client: "mihomo", Version: "1.19.32", Evidence: "docs/reports/PHASE19_NATIVE_VMESS_IMPLEMENTATION_REPORT.md"}, {Format: ports.URI, Client: "uri", Evidence: "docs/architecture/VMESS_RUNTIME.md"}}}
}
func (Module) ValidateInbound(i access.Inbound) error {
	if i.Validate() != nil || i.Protocol != Key() || i.Engine != "native" || !i.Enabled || len(i.Listeners) != 1 || i.Listeners[0].Transport != "tcp" || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	_, err := Decode(i.Settings.Data)
	return err
}
func (Module) ValidateCredential(c access.Credential) error {
	p, ok := c.Payload.(access.UUIDPayload)
	if !ok || c.Validate() != nil || c.Kind != access.UUID || c.State != "active" || p.Validate() != nil {
		return InvalidCredential()
	}
	return nil
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if err := m.ValidateInbound(in.Inbound); err != nil {
		return in, err
	}
	if len(in.Bindings) != len(in.Credentials) || len(in.Bindings) > 16 || len(in.ServerCredentials) != 0 {
		return in, invalid()
	}
	ids, keys := map[identity.ID]bool{}, map[wire.Key]bool{}
	for i, b := range in.Bindings {
		c := in.Credentials[i]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil {
			return in, invalid()
		}
		k := CommandKey(c.Payload.(access.UUIDPayload))
		if keys[k] {
			return in, invalid()
		}
		keys[k], ids[b.ID] = true, true
	}
	return in, nil
}
func (m Module) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, err := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}}); err != nil {
		return clientprofile.Profile{}, err
	}
	s, _ := Decode(b.Inbound.Settings.Data)
	opts, _ := json.Marshal(ClientOptions{Security: s.PayloadSecurity, UDP: true})
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: opts}, Metadata: identity.Metadata{}}
	if s.Security == "tls" {
		p.TLS = access.ClientTLS{Enabled: true, ServerName: s.TLS.ServerName, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate, ALPN: s.ALPN}
	}
	return p, p.Validate()
}
func ValidateClientNode(n client.RemoteNode, c access.Credential) error {
	if n.Protocol == Key() && n.Transport.Kind != "tcp" {
		return Unsupported("unsupported_transport")
	}
	if n.Validate() != nil || n.Protocol != Key() || n.Transport.Kind != "tcp" || (n.Security.Kind != "none" && n.Security.Kind != "tls") || c.OwnerNodeID == nil || *c.OwnerNodeID != n.ID || c.ID != n.CredentialID {
		return invalid()
	}
	if _, err := DecodeClientOptions(n.Options.Data); err != nil {
		return err
	}
	return (Module{}).ValidateCredential(c)
}
