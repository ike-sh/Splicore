// Package shadowsocks owns the managed AEAD 2017/2022 contracts.
package shadowsocks

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
)

type Method struct {
	Name, Edition string
	KeySize       int
	Identity      bool
}

// Methods returns a copy; callers cannot mutate protocol registration.
func Methods() []Method {
	return []Method{
		{"aes-128-gcm", "2017", 16, false}, {"aes-256-gcm", "2017", 32, false}, {"chacha20-ietf-poly1305", "2017", 32, false},
		{"2022-blake3-aes-128-gcm", "2022", 16, true}, {"2022-blake3-aes-256-gcm", "2022", 32, true}, {"2022-blake3-chacha20-poly1305", "2022", 32, false},
	}
}
func Lookup(name string) (Method, error) {
	for _, m := range Methods() {
		if m.Name == name {
			return m, nil
		}
	}
	return Method{}, identity.Err(identity.Invalid, "shadowsocks: unsupported method")
}
func Key(edition string) access.ProtocolKey {
	return access.ProtocolKey{Protocol: "shadowsocks", WireVersion: edition, FeatureProfile: "base"}
}

type Module struct{ Edition string }
type Settings struct {
	Method    string `json:"method"`
	MultiUser bool   `json:"multi_user"`
	UDP       bool   `json:"udp"`
}
type ClientOptions struct {
	Method string `json:"method"`
	UDP    bool   `json:"udp"`
}

func invalid() error {
	return identity.Err(identity.Invalid, "invalid shadowsocks settings or credential")
}
func (Settings) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ShadowsocksSettings{[REDACTED]}"))
}
func Decode(b []byte) (Settings, error) {
	var w struct {
		Method string        `json:"method"`
		Multi  creation.Flag `json:"multi_user"`
		UDP    creation.Flag `json:"udp"`
	}
	if jsonstrict.Decode(b, &w) != nil {
		return Settings{}, invalid()
	}
	m, e := Lookup(w.Method)
	if e != nil {
		return Settings{}, e
	}
	s := Settings{w.Method, w.Multi.Value, creation.Enabled(w.UDP)}
	if s.MultiUser && !m.Identity {
		return s, identity.Err(identity.Invalid, "shadowsocks: incompatible multi-user mode")
	}
	return s, nil
}
func DecodeClient(b []byte) (ClientOptions, error) {
	var w struct {
		Method string        `json:"method"`
		UDP    creation.Flag `json:"udp"`
	}
	if jsonstrict.Decode(b, &w) != nil {
		return ClientOptions{}, invalid()
	}
	if _, e := Lookup(w.Method); e != nil {
		return ClientOptions{}, e
	}
	return ClientOptions{w.Method, creation.Enabled(w.UDP)}, nil
}
func DecodeKeys(method, value string, chain bool) ([][]byte, error) {
	m, e := Lookup(method)
	if e != nil || m.Edition != "2022" || len(value) > 4096 {
		return nil, invalid()
	}
	parts := strings.Split(value, ":")
	if len(parts) > 8 || (!chain || !m.Identity) && len(parts) != 1 {
		return nil, identity.Err(identity.Invalid, "shadowsocks: invalid identity key chain")
	}
	keys := make([][]byte, 0, len(parts))
	for _, p := range parts {
		b, e := base64.StdEncoding.Strict().DecodeString(p)
		if e != nil || len(b) != m.KeySize || base64.StdEncoding.EncodeToString(b) != p {
			return nil, identity.Err(identity.Invalid, "shadowsocks: invalid PSK encoding or length")
		}
		keys = append(keys, b)
	}
	return keys, nil
}
func Material(p access.Payload) string {
	switch v := p.(type) {
	case access.PasswordPayload:
		return v.Password.Reveal()
	case access.PSKPayload:
		return v.Key.Reveal()
	}
	return ""
}
func ValidateMaterial(method string, p access.Payload, chain bool) error {
	m, e := Lookup(method)
	if e != nil {
		return e
	}
	if m.Edition == "2022" {
		if p == nil || p.Kind() != access.PSK {
			return invalid()
		}
		_, e := DecodeKeys(method, Material(p), chain)
		return e
	}
	v, ok := p.(access.PasswordPayload)
	if !ok || v.Validate() != nil || !utf8.ValidString(v.Password.Reveal()) || strings.ContainsAny(v.Password.Reveal(), "\x00\r\n") {
		return invalid()
	}
	return nil
}
func Generate(method string) (access.Payload, error) {
	m, e := Lookup(method)
	if e != nil {
		return nil, e
	}
	b := make([]byte, m.KeySize)
	if _, e = rand.Read(b); e != nil {
		return nil, identity.Err(identity.Unavailable, "credential entropy unavailable")
	}
	v := secret.New(base64.StdEncoding.EncodeToString(b))
	clear(b)
	if m.Edition == "2017" {
		return access.PasswordPayload{Password: v}, nil
	}
	return access.PSKPayload{Key: v}, nil
}
func (m Module) Metadata() ports.ProtocolMetadata {
	k := access.Password
	if m.Edition == "2022" {
		k = access.PSK
	}
	return ports.ProtocolMetadata{Roles: ports.Roles{Inbound: true, Outbound: true}, Key: Key(m.Edition), ABI: 1, CredentialKinds: []access.CredentialKind{k}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "canonical AEAD/SIP022/SIP023; Splicore lifecycle; standard crypto and pinned BLAKE3"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{Transport: ports.TransportCapabilities{Kinds: []string{"tcp", "udp"}, TCP: true, UDPTransport: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Identity: ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; runtime generation"}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}}
}
func (m Module) ValidateInbound(i access.Inbound) error {
	if e := i.Validate(); e != nil {
		return e
	}
	s, e := Decode(i.Settings.Data)
	if e != nil {
		return e
	}
	method, _ := Lookup(s.Method)
	count := 1
	if s.UDP {
		count = 2
	}
	if method.Edition != m.Edition || i.Protocol != Key(m.Edition) || i.Engine != "native" || !i.Enabled || len(i.Listeners) != count || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	seen := map[string]bool{}
	for _, l := range i.Listeners {
		if seen[l.Transport] || l.Endpoint != i.Listeners[0].Endpoint || l.Transport != "tcp" && (!s.UDP || l.Transport != "udp") {
			return invalid()
		}
		seen[l.Transport] = true
	}
	if !seen["tcp"] {
		return invalid()
	}
	return nil
}
func (m Module) ValidateCredential(c access.Credential) error {
	if c.Validate() != nil || c.State != "active" {
		return invalid()
	}
	if m.Edition == "2017" {
		return ValidateMaterial("aes-256-gcm", c.Payload, false)
	}
	if c.Kind != access.PSK {
		return invalid()
	}
	// Exact method lengths are checked with the owning inbound/node settings.
	for _, name := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		if ValidateMaterial(name, c.Payload, c.OwnerNodeID != nil) == nil {
			return nil
		}
	}
	return invalid()
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if e := m.ValidateInbound(in.Inbound); e != nil {
		return in, e
	}
	s, _ := Decode(in.Inbound.Settings.Data)
	method, _ := Lookup(s.Method)
	if len(in.Bindings) != len(in.Credentials) || len(in.Bindings) > 16 || method.Edition == "2022" && !s.MultiUser && len(in.Bindings) > 1 {
		return in, invalid()
	}
	if s.MultiUser {
		if len(in.ServerCredentials) != 1 {
			return in, identity.Err(identity.Invalid, "shadowsocks: missing server credential")
		}
		c := in.ServerCredentials[0]
		if c.Validate() != nil || c.State != "active" || c.OwnerInboundID == nil || *c.OwnerInboundID != in.Inbound.ID || ValidateMaterial(s.Method, c.Payload, false) != nil {
			return in, invalid()
		}
	} else if len(in.ServerCredentials) != 0 {
		return in, invalid()
	}
	seen, ids := map[string]bool{}, map[identity.ID]bool{}
	for n, b := range in.Bindings {
		c := in.Credentials[n]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil || ValidateMaterial(s.Method, c.Payload, false) != nil {
			return in, invalid()
		}
		v := Material(c.Payload)
		if seen[v] {
			return in, identity.Err(identity.Invalid, "shadowsocks: duplicate identity")
		}
		seen[v] = true
		ids[b.ID] = true
	}
	return in, nil
}
func (m Module) ClientServerCredentials() bool { return m.Edition == "2022" }
func (m Module) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	in := ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}, ServerCredentials: b.ServerCredentials}
	if _, e := m.BuildRuntime(ctx, in); e != nil {
		return clientprofile.Profile{}, e
	}
	s, _ := Decode(b.Inbound.Settings.Data)
	payload := b.Credential.Payload
	if s.MultiUser {
		payload = access.PSKPayload{Key: secret.New(Material(b.ServerCredentials[0].Payload) + ":" + Material(payload))}
	}
	raw, _ := json.Marshal(ClientOptions{s.Method, s.UDP})
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(m.Edition), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: payload, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: s.UDP, Options: access.Settings{Schema: 1, Data: raw}, Metadata: identity.Metadata{}}
	return p, p.Validate()
}
