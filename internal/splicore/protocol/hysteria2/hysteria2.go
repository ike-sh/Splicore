// Package hysteria2 owns the bounded managed profile, never QUIC/TLS wire code.
package hysteria2

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	streamcfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
)

type Module struct{}
type TLSSettings = tlsconfig.Settings

func CAPool(s string) (*x509.CertPool, error) { return tlsconfig.CAPool(s) }
func CAFingerprint(s string) (string, error)  { return tlsconfig.CAFingerprint(s) }
func ValidatePassword(s secret.Value) error   { return credential.ValidatePassword(s) }
func GeneratePassword() (secret.Value, error) { return credential.GeneratePassword() }

type Settings struct {
	TLS             TLSSettings       `json:"tls"`
	StreamTransport *streamcfg.Config `json:"stream_transport,omitempty"`
}

func (s Settings) Transport() streamcfg.Config {
	if s.StreamTransport != nil {
		return s.StreamTransport.Clone()
	}
	return streamcfg.Config{Kind: "hysteria"}
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
func Decode(b []byte) (Settings, error) {
	var s Settings
	if len(b) > 16384 || streamcfg.ValidateMember(b) != nil || jsonstrict.Decode(b, &s) != nil || tlsconfig.Validate(s.TLS) != nil || s.Transport().Type() != "hysteria" || s.Transport().ValidateServer() != nil {
		return s, invalid()
	}
	return s, nil
}
func (Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Roles: ports.Roles{Inbound: true, Outbound: true}, Key: Key(), ABI: 1, CredentialKinds: []access.CredentialKind{access.Password}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "Splicore-owned Hysteria2 wire/lifecycle; independent AperNet QUIC; password identity; static TLS; native Salamander/Gecko and UDP hopping"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{
		Transport: ports.TransportCapabilities{TCP: true, UDPTransport: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true},
		Identity:  ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; runtime generation"},
		Security:  ports.SecurityCapabilities{TLS: true}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported},
		Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable},
		Clients:  []ports.ClientCompatibility{{Format: ports.Mihomo, Client: "mihomo", Version: "1.19.30", Evidence: ""}, {Format: ports.SingBox, Client: "sing-box", Version: "1.14.1", Evidence: ""}},
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
	s, _ := Decode(i.Settings.Data)
	if u := s.Transport().HysteriaSettings().UDP; u != nil && u.ServerPortRange != "" {
		lo, _, e := streamcfg.HysteriaServerRange(u.ServerPortRange)
		if e != nil || i.Listeners[0].Endpoint.Port != lo {
			return invalid()
		}
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
	transport := s.Transport()
	clientSettings := transport.HysteriaSettings().ClientProfile()
	if clientSettings.Obfs != nil || clientSettings.UDP != nil {
		transport.Hysteria = &clientSettings
	} else {
		transport.Hysteria = nil
	}
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, TLS: clientprofile.TLS{Enabled: true, ServerName: s.TLS.ServerName, ALPN: []string{"h3"}, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}, Transport: transport, UDPPayload: !s.Transport().HysteriaSettings().DisableUDP, Options: access.Settings{Schema: 1, Data: options}, Metadata: identity.Metadata{}}
	return p, p.Validate()
}
