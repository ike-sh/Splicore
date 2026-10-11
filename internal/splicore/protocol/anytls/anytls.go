// Package anytls owns managed AnyTLS settings, credentials and neutral profiles.
package anytls

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/protocol/anytls/padding"
	"github.com/ike-sh/Splicore/protocol/anytls/session"
	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

type Module struct{}

func Key() access.ProtocolKey {
	return access.ProtocolKey{Protocol: "anytls", WireVersion: "2", FeatureProfile: "base"}
}
func invalid() error { return identity.Err(identity.Invalid, "invalid AnyTLS settings or credential") }

type Settings struct {
	TLS           tlsconfig.Settings `json:"tls"`
	ALPN          []string           `json:"alpn,omitempty"`
	PaddingScheme string             `json:"padding_scheme,omitempty"`
	Version       int                `json:"version,omitempty"`
	MaxSessions   int                `json:"max_sessions,omitempty"`
	MaxStreams    int                `json:"max_streams,omitempty"`
}

func (Settings) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("AnyTLSSettings{[REDACTED]}")) }
func topFields(b []byte) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil {
		return nil, invalid()
	}
	for _, v := range fields {
		if strings.TrimSpace(string(v)) == "null" {
			return nil, invalid()
		}
	}
	return fields, nil
}
func Decode(b []byte) (Settings, error) {
	var s Settings
	fields, err := topFields(b)
	if err != nil || len(b) > 16384 || jsonstrict.Decode(b, &s) != nil || tlsconfig.Validate(s.TLS) != nil {
		return s, invalid()
	}
	if _, present := fields["version"]; present && s.Version != 1 && s.Version != 2 {
		return s, invalid()
	}
	if s.Version == 0 {
		s.Version = 2
	}
	if s.MaxSessions == 0 {
		s.MaxSessions = 512
	}
	if s.MaxStreams == 0 {
		s.MaxStreams = 128
	}
	if s.MaxSessions < 1 || s.MaxSessions > 512 || s.MaxStreams < 1 || s.MaxStreams > 128 {
		return s, invalid()
	}
	if s.PaddingScheme == "" {
		s.PaddingScheme = padding.Default
	}
	if _, err := padding.Parse(s.PaddingScheme); err != nil {
		return s, invalid()
	}
	if (access.ClientTLS{Enabled: true, ServerName: s.TLS.ServerName, ALPN: s.ALPN, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}).Validate("tls") != nil {
		return s, invalid()
	}
	return s, nil
}

type ClientOptions struct {
	UDP              bool   `json:"udp"`
	Version          int    `json:"version,omitempty"`
	IdleCheck        string `json:"idle_session_check_interval,omitempty"`
	IdleTimeout      string `json:"idle_session_timeout,omitempty"`
	MinIdle          int    `json:"min_idle_session,omitempty"`
	MaxSessions      int    `json:"max_sessions,omitempty"`
	MultiplexStreams int    `json:"multiplex_streams,omitempty"`
	ClientMetadata   string `json:"client_metadata,omitempty"`
	Insecure         bool   `json:"insecure,omitempty"`
	UOTMode          string `json:"uot_mode,omitempty"`
}

func (ClientOptions) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("AnyTLSClientOptions{[REDACTED]}"))
}
func DecodeClientOptions(b []byte) (ClientOptions, error) {
	var o ClientOptions
	fields, err := topFields(b)
	if err != nil || len(b) > 16384 || jsonstrict.Decode(b, &o) != nil {
		return o, invalid()
	}
	var flag struct {
		UDP creation.Flag `json:"udp"`
	}
	if data, ok := fields["udp"]; ok {
		if json.Unmarshal(data, &flag.UDP) != nil {
			return o, invalid()
		}
	}
	o.UDP = creation.Enabled(flag.UDP)
	if _, ok := fields["version"]; ok && o.Version != 1 && o.Version != 2 {
		return o, invalid()
	}
	if o.Version == 0 {
		o.Version = 2
	}
	if o.IdleCheck == "" {
		if _, ok := fields["idle_session_check_interval"]; ok {
			return o, invalid()
		}
		o.IdleCheck = "30s"
	}
	if o.IdleTimeout == "" {
		if _, ok := fields["idle_session_timeout"]; ok {
			return o, invalid()
		}
		o.IdleTimeout = "30s"
	}
	interval, e1 := time.ParseDuration(o.IdleCheck)
	timeout, e2 := time.ParseDuration(o.IdleTimeout)
	if e1 != nil || e2 != nil || interval < time.Millisecond || interval > time.Hour || timeout < time.Millisecond || timeout > 24*time.Hour {
		return o, invalid()
	}
	if o.MaxSessions == 0 {
		o.MaxSessions = 128
	}
	if o.MultiplexStreams == 0 {
		o.MultiplexStreams = 1
	}
	if o.MaxSessions < 1 || o.MaxSessions > 128 || o.MinIdle < 0 || o.MinIdle > o.MaxSessions || o.MultiplexStreams < 1 || o.MultiplexStreams > 128 {
		return o, invalid()
	}
	if len(o.ClientMetadata) > 128 || strings.ContainsAny(o.ClientMetadata, "\r\n\x00") || o.ClientMetadata != "" && o.ClientMetadata != "splicore" && !strings.HasPrefix(o.ClientMetadata, "splicore/") {
		return o, invalid()
	}
	if o.UOTMode == "" {
		o.UOTMode = "non_connect"
	}
	if o.UOTMode != "connect" && o.UOTMode != "non_connect" {
		return o, invalid()
	}
	return o, nil
}
func (o ClientOptions) PoolConfig() session.PoolConfig {
	check, _ := time.ParseDuration(o.IdleCheck)
	timeout, _ := time.ParseDuration(o.IdleTimeout)
	return session.PoolConfig{Session: session.Config{Version: o.Version, ClientMetadata: o.ClientMetadata}, IdleCheck: check, IdleTimeout: timeout, MinIdle: o.MinIdle, MaxSessions: o.MaxSessions, MultiplexStreams: o.MultiplexStreams}
}

func (Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Roles: ports.Roles{Inbound: true, Outbound: true}, Key: Key(), ABI: 1, CredentialKinds: []access.CredentialKind{access.Password}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "independent Splicore implementation of public AnyTLS v2/v1 and UoT2 specifications; TLS required"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{Transport: ports.TransportCapabilities{TCP: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Identity: ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; logical streams; runtime generation"}, Security: ports.SecurityCapabilities{TLS: true}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}, Clients: []ports.ClientCompatibility{{Format: ports.URI, Client: "uri"}, {Format: ports.SingBox, Client: "sing-box", Version: "1.14.2"}}}
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
	bindings, auth := map[identity.ID]bool{}, map[wire.AuthKey]bool{}
	for i, b := range in.Bindings {
		c := in.Credentials[i]
		if b.Validate() != nil || !b.Enabled || bindings[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil {
			return in, invalid()
		}
		key := wire.PasswordKey(c.Payload.(access.PasswordPayload).Password.Reveal())
		if auth[key] {
			return in, invalid()
		}
		auth[key], bindings[b.ID] = true, true
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
	return p, p.Validate()
}
func ValidateClientNode(n client.RemoteNode, c access.Credential) error {
	if n.Validate() != nil || n.Protocol != Key() || n.Security.Kind != "tls" || n.Transport.Type() != "tcp" || n.Transport.ValidatePair("anytls", "tls") != nil || c.OwnerNodeID == nil || *c.OwnerNodeID != n.ID || c.ID != n.CredentialID {
		return invalid()
	}
	if _, err := access.ParseHost(n.Security.TLS.ServerName); err != nil {
		return invalid()
	}
	o, err := DecodeClientOptions(n.Options.Data)
	if err != nil {
		return err
	}
	if o.Insecure && (n.Security.TLS.Trust != "system" || n.Security.TLS.CACertificate != "") {
		return invalid()
	}
	return (Module{}).ValidateCredential(c)
}
