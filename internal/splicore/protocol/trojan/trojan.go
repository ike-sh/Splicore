// Package trojan owns the managed standard Trojan profile and credential boundary.
package trojan

import (
	"context"
	"encoding/json"
	"fmt"
	streamcfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/protocol/trojan/wire"
)

type Module struct{}
type Settings struct {
	Stream *streamcfg.Config  `json:"stream_transport,omitempty"`
	TLS    tlsconfig.Settings `json:"tls"`
	ALPN   []string           `json:"alpn,omitempty"`
}

func (Settings) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("TrojanSettings{[REDACTED]}")) }
func Key() access.ProtocolKey {
	return access.ProtocolKey{Protocol: "trojan", WireVersion: "standard", FeatureProfile: "base"}
}
func invalid() error {
	return identity.Err(identity.Invalid, "unsupported standard Trojan settings or credential")
}
func Decode(b []byte) (Settings, error) {
	var s Settings
	if len(b) > 16384 || streamcfg.ValidateMember(b) != nil || jsonstrict.Decode(b, &s) != nil || tlsconfig.Validate(s.TLS) != nil || s.Stream != nil && (s.Stream.ValidatePair("trojan", "tls") != nil || s.Stream.ValidateServer() != nil || s.Stream.ValidateALPN(s.ALPN) != nil) {
		return s, invalid()
	}
	t := access.ClientTLS{Enabled: true, ServerName: s.TLS.ServerName, ALPN: s.ALPN, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}
	if t.Validate("tls") != nil {
		return s, invalid()
	}
	return s, nil
}

type ClientOptions struct {
	UDP bool `json:"udp"`
}

func DecodeClientOptions(b []byte) (ClientOptions, error) {
	var v struct {
		UDP creation.Flag `json:"udp"`
	}
	if len(b) > 16384 || jsonstrict.Decode(b, &v) != nil {
		return ClientOptions{}, invalid()
	}
	return ClientOptions{UDP: creation.Enabled(v.UDP)}, nil
}
func (Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Roles: ports.Roles{Inbound: true, Outbound: true}, Key: Key(), ABI: 1, CredentialKinds: []access.CredentialKind{access.Password}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "Splicore-owned standard Trojan TLS/TCP/UDP; SHA-224 authentication; fallback deferred; no mux/extensions"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{Transport: ports.TransportCapabilities{TCP: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Identity: ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; runtime generation"}, Security: ports.SecurityCapabilities{TLS: true}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}, Clients: []ports.ClientCompatibility{{Format: ports.SingBox, Client: "sing-box", Version: "1.14.1", Evidence: "docs/reports/PHASE18_NATIVE_TROJAN_IMPLEMENTATION_REPORT.md"}, {Format: ports.Mihomo, Client: "mihomo", Version: "1.19.30", Evidence: "docs/reports/PHASE18_NATIVE_TROJAN_IMPLEMENTATION_REPORT.md"}, {Format: ports.URI, Client: "uri", Evidence: "docs/architecture/TROJAN_RUNTIME.md"}}}
}
func (Module) ValidateInbound(i access.Inbound) error {
	if i.Validate() != nil || i.Protocol != Key() || i.Engine != "native" || !i.Enabled || len(i.Listeners) != 1 || i.Listeners[0].Transport != "tcp" || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	_, err := Decode(i.Settings.Data)
	return err
}
func (Module) ValidateCredential(c access.Credential) error {
	p, ok := c.Payload.(access.PasswordPayload)
	if c.Validate() != nil || c.Kind != access.Password || c.State != "active" || !ok || credential.ValidatePassword(p.Password) != nil {
		return invalid()
	}
	return nil
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if m.ValidateInbound(in.Inbound) != nil || len(in.Bindings) != len(in.Credentials) || len(in.Bindings) > 16 {
		return in, invalid()
	}
	ids, keys := map[identity.ID]bool{}, map[wire.Key]bool{}
	for i, b := range in.Bindings {
		c := in.Credentials[i]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil {
			return in, invalid()
		}
		k := wire.Derive(c.Payload.(access.PasswordPayload).Password)
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
	options, _ := json.Marshal(ClientOptions{UDP: true})
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, TLS: access.ClientTLS{Enabled: true, ServerName: s.TLS.ServerName, ALPN: s.ALPN, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: options}, Metadata: identity.Metadata{}}
	if s.Stream != nil {
		p.Transport = *s.Stream
	}
	return p, p.Validate()
}
func ValidateClientNode(n client.RemoteNode, c access.Credential) error {
	if n.Validate() != nil || n.Protocol != Key() || n.Transport.ValidatePair("trojan", n.Security.Kind) != nil || n.Security.Kind != "tls" || c.OwnerNodeID == nil || *c.OwnerNodeID != n.ID || c.ID != n.CredentialID {
		return invalid()
	}
	if _, err := access.ParseHost(n.Security.TLS.ServerName); err != nil {
		return invalid()
	}
	if _, err := DecodeClientOptions(n.Options.Data); err != nil {
		return err
	}
	return (Module{}).ValidateCredential(c)
}
