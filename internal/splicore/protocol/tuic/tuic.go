// Package tuic owns the bounded TUIC v5 managed profile, never wire code.
package tuic

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid/v5"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"strings"
)

type Module struct{}
type Settings struct {
	TLS               tlsconfig.Settings `json:"tls"`
	Version           int                `json:"version"`
	CongestionControl string             `json:"congestion_control"`
	UDPRelayMode      string             `json:"udp_relay_mode"`
	ZeroRTT           bool               `json:"zero_rtt_handshake"`
}

func (Settings) Format(s fmt.State, v rune) { _, _ = s.Write([]byte("TUICSettings{[REDACTED]}")) }
func Key() access.ProtocolKey {
	return access.ProtocolKey{Protocol: "tuic", WireVersion: "5", FeatureProfile: "base"}
}
func invalid() error {
	return identity.Err(identity.Invalid, "unsupported TUIC settings or credential")
}
func Decode(b []byte) (Settings, error) {
	type wire Settings
	var w struct {
		wire
		ZeroRTT creation.Flag `json:"zero_rtt_handshake"`
	}
	if len(b) > 16384 || jsonstrict.Decode(b, &w) != nil {
		return Settings{}, invalid()
	}
	s := Settings(w.wire)
	s.ZeroRTT = w.ZeroRTT.Value
	if tlsconfig.Validate(s.TLS) != nil || s.Version != 5 || s.CongestionControl != "cubic" || s.UDPRelayMode != "native" || s.ZeroRTT {
		return s, invalid()
	}
	return s, nil
}
func ValidateUUID(v secret.Value) error {
	value := v.Reveal()
	u, err := uuid.FromString(value)
	if err != nil || len(value) != 36 || strings.ToLower(value) != u.String() || u == uuid.Nil {
		return invalid()
	}
	return nil
}
func GenerateCredential() (access.Payload, error) {
	id, err := identity.NewID()
	if err != nil {
		return nil, err
	}
	pass, err := credential.GeneratePassword()
	if err != nil {
		return nil, err
	}
	return access.UUIDPasswordPayload{UUID: secret.New(string(id)), Password: pass}, nil
}
func (Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Roles: ports.Roles{Inbound: true, Outbound: true}, Key: Key(), ABI: 1, CredentialKinds: []access.CredentialKind{access.UUIDPassword}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "Splicore-owned TUIC v5 wire/lifecycle; independent quic-go; UUID+password; static TLS; cubic/native; 0-RTT disabled"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{Transport: ports.TransportCapabilities{TCP: true, UDPTransport: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Identity: ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; runtime generation"}, Security: ports.SecurityCapabilities{TLS: true}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}, Clients: []ports.ClientCompatibility{{Format: ports.Mihomo, Client: "mihomo", Version: "1.19.30", Evidence: ""}, {Format: ports.SingBox, Client: "sing-box", Version: "1.14.1", Evidence: ""}}}
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
	p, ok := c.Payload.(access.UUIDPasswordPayload)
	if c.Validate() != nil || c.Kind != access.UUIDPassword || c.State != "active" || !ok || ValidateUUID(p.UUID) != nil || credential.ValidatePassword(p.Password) != nil {
		return invalid()
	}
	return nil
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if err := m.ValidateInbound(in.Inbound); err != nil {
		return in, err
	}
	if len(in.Bindings) != len(in.Credentials) || len(in.Bindings) > 16 {
		return in, invalid()
	}
	ids, uuids := map[identity.ID]bool{}, map[string]bool{}
	for n, b := range in.Bindings {
		c := in.Credentials[n]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil {
			return in, invalid()
		}
		ids[b.ID] = true
		key := strings.ToLower(c.Payload.(access.UUIDPasswordPayload).UUID.Reveal())
		if uuids[key] {
			return in, invalid()
		}
		uuids[key] = true
	}
	return in, nil
}
func (m Module) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, err := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}}); err != nil {
		return clientprofile.Profile{}, err
	}
	s, _ := Decode(b.Inbound.Settings.Data)
	options, _ := json.Marshal(ClientOptions{Version: 5, CongestionControl: s.CongestionControl, UDPRelayMode: s.UDPRelayMode})
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, TLS: clientprofile.TLS{Enabled: true, ServerName: s.TLS.ServerName, ALPN: []string{"h3"}, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}, Transport: clientprofile.Transport{Kind: "quic"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: options}, Metadata: identity.Metadata{}}
	return p, p.Validate()
}

type ClientOptions struct {
	Version           int    `json:"version"`
	CongestionControl string `json:"congestion_control"`
	UDPRelayMode      string `json:"udp_relay_mode"`
	ZeroRTT           bool   `json:"zero_rtt_handshake"`
}

func DecodeClientOptions(b []byte) (ClientOptions, error) {
	type wire ClientOptions
	var w struct {
		wire
		ZeroRTT creation.Flag `json:"zero_rtt_handshake"`
	}
	if len(b) > 16384 || jsonstrict.Decode(b, &w) != nil {
		return ClientOptions{}, invalid()
	}
	o := ClientOptions(w.wire)
	o.ZeroRTT = w.ZeroRTT.Value
	if o.Version != 5 || o.CongestionControl != "cubic" || o.UDPRelayMode != "native" || o.ZeroRTT {
		return o, invalid()
	}
	return o, nil
}
