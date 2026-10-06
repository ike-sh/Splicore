// Package snell validates the managed Snell profile; it contains no wire protocol.
package snell

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"io"
	"strconv"
)

type Module struct{ Version int }
type Settings struct {
	Version int `json:"version"`
}

func Key(v int) access.ProtocolKey {
	return access.ProtocolKey{Protocol: "snell", WireVersion: strconv.Itoa(v), FeatureProfile: "base"}
}

// Decode rejects unknown fields, duplicate keys, trailing input and non-integer versions.
func Decode(b []byte) (Settings, error) {
	if len(b) > 16384 {
		return Settings{}, invalid()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return Settings{}, invalid()
	}
	var s Settings
	seen := false
	for d.More() {
		t, e = d.Token()
		if e != nil || t != "version" || seen {
			return Settings{}, invalid()
		}
		seen = true
		if d.Decode(&s.Version) != nil {
			return Settings{}, invalid()
		}
	}
	t, e = d.Token()
	if e != nil || t != json.Delim('}') || !seen {
		return Settings{}, invalid()
	}
	if d.Decode(new(any)) != io.EOF || (s.Version != 5 && s.Version != 6) {
		return Settings{}, invalid()
	}
	return s, nil
}
func invalid() error {
	return identity.Err(identity.Invalid, "unsupported Snell settings or credential")
}
func (m Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Roles: ports.Roles{Inbound: true, Outbound: true}, Key: Key(m.Version), ABI: 1, CredentialKinds: []access.CredentialKind{access.PSK}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "Splicore-owned Snell wire and lifecycle; single binding; no QUIC proxy mode"}
}

// ClientVersion is the canonical, explicit server-to-client compatibility mapping.
func ClientVersion(server int) (int, error) {
	switch server {
	case 5:
		return 4, nil
	case 6:
		return 6, nil
	default:
		return 0, invalid()
	}
}
func (m Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	clients := []ports.ClientCompatibility{{Format: ports.SingBox, Client: "sing-box", Version: "1.14.1", Evidence: "docs/reports/PHASE17_SINGBOX_DECOUPLING_REPORT.md; Round 2 Linux TCP/UDP v4/v6"}}
	if m.Version == 5 {
		clients = append(clients, ports.ClientCompatibility{Format: ports.Mihomo, Client: "mihomo", Version: "1.19.30", Evidence: "docs/reports/PHASE17_SINGBOX_DECOUPLING_REPORT.md; Round 2 explicit v4 client / v5 server"})
	}
	return ports.Capabilities{Transport: ports.TransportCapabilities{TCP: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Identity: ports.IdentityCapabilities{MultiUserNative: false, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; process lifetime"}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.MutationUnavailable, Listener: ports.MutationUnavailable}, Clients: clients}
}
func (m Module) ValidateInbound(i access.Inbound) error {
	if e := i.Validate(); e != nil {
		return e
	}
	s, e := Decode(i.Settings.Data)
	if e != nil || i.Protocol != Key(m.Version) || s.Version != m.Version || i.Engine != "native" || !i.Enabled || len(i.Listeners) != 1 || i.Listeners[0].Transport != "tcp" || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	return nil
}

// Portable managed PSKs use 12..255 ASCII bytes without client delimiters.
// This is a deliberately narrower profile than the v5 native nonempty-key contract.
func ValidatePSK(v secret.Value) error {
	s := v.Reveal()
	if len(s) < 12 || len(s) > 255 {
		return invalid()
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '+' || c == '/' || c == '=') {
			return invalid()
		}
	}
	return nil
}
func GeneratePSK() (secret.Value, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return secret.Value{}, identity.Err(identity.Unavailable, "credential entropy unavailable")
	}
	return secret.New(base64.RawURLEncoding.EncodeToString(b[:])), nil
}
func (m Module) ValidateCredential(c access.Credential) error {
	if e := c.Validate(); e != nil {
		return e
	}
	p, ok := c.Payload.(access.PSKPayload)
	if !ok || c.Kind != access.PSK || c.State != "active" {
		return invalid()
	}
	return ValidatePSK(p.Key)
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if e := m.ValidateInbound(in.Inbound); e != nil {
		return ports.RuntimeIntent{}, e
	}
	if len(in.Bindings) != 1 || len(in.Credentials) != 1 {
		return ports.RuntimeIntent{}, invalid()
	}
	b, c := in.Bindings[0], in.Credentials[0]
	if e := b.Validate(); e != nil {
		return ports.RuntimeIntent{}, e
	}
	if !b.Enabled || b.PolicyOverrideID != nil || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID {
		return ports.RuntimeIntent{}, invalid()
	}
	if e := m.ValidateCredential(c); e != nil {
		return ports.RuntimeIntent{}, e
	}
	return in, nil
}
func (m Module) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, e := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}}); e != nil {
		return clientprofile.Profile{}, e
	}
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(m.Version), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: true, Options: b.Inbound.Settings, Metadata: identity.Metadata{}}
	return p, p.Validate()
}
