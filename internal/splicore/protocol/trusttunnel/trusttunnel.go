// Package trusttunnel owns first-class TrustTunnel intent. HTTP modes are
// protocol session choices, never generic stream transport capabilities.
package trusttunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/session"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
	"golang.org/x/net/http/httpguts"
)

type Module struct{}

func Key() access.ProtocolKey {
	return access.ProtocolKey{Protocol: "trusttunnel", WireVersion: "1", FeatureProfile: "base"}
}
func invalid() error {
	return identity.Err(identity.Invalid, "invalid TrustTunnel settings or credential")
}

type Settings struct {
	TLS            tlsconfig.Settings `json:"tls"`
	Mode           string             `json:"mode"`
	MaxStreams     int                `json:"max_streams,omitempty"`
	MaxSessions    int                `json:"max_sessions,omitempty"`
	MaxFlows       int                `json:"max_flows,omitempty"`
	ConnectTimeout string             `json:"connect_timeout,omitempty"`
	IdleTimeout    string             `json:"idle_timeout,omitempty"`
	UDPIdleTimeout string             `json:"udp_idle_timeout,omitempty"`
	ICMP           bool               `json:"icmp,omitempty"`
}
type ClientOptions struct {
	Mode           string   `json:"mode"`
	Addresses      []string `json:"addresses,omitempty"`
	CustomSNI      string   `json:"custom_sni,omitempty"`
	Insecure       bool     `json:"insecure_skip_verification,omitempty"`
	DisableIPv6    bool     `json:"disable_ipv6,omitempty"`
	UserAgent      string   `json:"user_agent,omitempty"`
	MaxStreams     int      `json:"max_streams,omitempty"`
	MaxFlows       int      `json:"max_flows,omitempty"`
	ConnectTimeout string   `json:"connect_timeout,omitempty"`
	HealthTimeout  string   `json:"health_check_timeout,omitempty"`
	FallbackDelay  string   `json:"fallback_delay,omitempty"`
	IdleTimeout    string   `json:"idle_timeout,omitempty"`
	UDPIdleTimeout string   `json:"udp_idle_timeout,omitempty"`
}

func (Settings) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("TrustTunnelSettings{[REDACTED]}"))
}
func (ClientOptions) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("TrustTunnelOptions{[REDACTED]}"))
}
func fields(b []byte, allowed ...string) error {
	var obj map[string]json.RawMessage
	if len(b) > 16384 || jsonstrict.Decode(b, &obj) != nil || obj == nil {
		return invalid()
	}
	for k, v := range obj {
		known := false
		for _, a := range allowed {
			known = known || k == a
		}
		if !known || strings.TrimSpace(string(v)) == "null" {
			return invalid()
		}
	}
	return nil
}
func Duration(v, def string) (time.Duration, error) {
	if v == "" {
		v = def
	}
	d, e := time.ParseDuration(v)
	if e != nil || d < time.Millisecond || d > 24*time.Hour {
		return 0, invalid()
	}
	return d, nil
}
func mode(v string) bool { return v == "http2" || v == "http3" || v == "auto" }
func Carrier(v string) string {
	if v == "http3" {
		return "udp"
	}
	return "tcp"
}
func Decode(b []byte) (Settings, error) {
	var s Settings
	if fields(b, "tls", "mode", "max_streams", "max_sessions", "max_flows", "connect_timeout", "idle_timeout", "udp_idle_timeout", "icmp") != nil || jsonstrict.Decode(b, &s) != nil || !mode(s.Mode) || tlsconfig.Validate(s.TLS) != nil {
		return s, invalid()
	}
	if s.MaxStreams == 0 {
		s.MaxStreams = 512
	}
	if s.MaxSessions == 0 {
		s.MaxSessions = 64
	}
	if s.MaxFlows == 0 {
		s.MaxFlows = 256
	}
	if s.MaxStreams < 4 || s.MaxStreams > 512 || s.MaxSessions < 1 || s.MaxSessions > 1024 || s.MaxFlows < 1 || s.MaxFlows > 4096 {
		return s, invalid()
	}
	for _, v := range []struct{ s, d string }{{s.ConnectTimeout, "30s"}, {s.IdleTimeout, "10m"}, {s.UDPIdleTimeout, "120s"}} {
		if _, e := Duration(v.s, v.d); e != nil {
			return s, e
		}
	}
	return s, nil
}
func DecodeClient(b []byte) (ClientOptions, error) {
	var o ClientOptions
	if fields(b, "mode", "addresses", "custom_sni", "insecure_skip_verification", "disable_ipv6", "user_agent", "max_streams", "max_flows", "connect_timeout", "health_check_timeout", "fallback_delay", "idle_timeout", "udp_idle_timeout") != nil || jsonstrict.Decode(b, &o) != nil || !mode(o.Mode) {
		return o, invalid()
	}
	if len(o.Addresses) > 16 {
		return o, invalid()
	}
	seen := map[string]bool{}
	a := []string{}
	for _, address := range o.Addresses {
		v, e := wire.Authority(address)
		if e != nil {
			return o, invalid()
		}
		if !seen[v] {
			seen[v] = true
			a = append(a, v)
		}
	}
	o.Addresses = a
	if o.CustomSNI != "" {
		kind, e := access.ParseHost(o.CustomSNI)
		if e != nil || kind != access.DNS {
			return o, invalid()
		}
	}
	if len(o.UserAgent) > 512 || !httpguts.ValidHeaderFieldValue(o.UserAgent) || strings.ContainsAny(o.UserAgent, "\x00\r\n") {
		return o, invalid()
	}
	if o.MaxStreams == 0 {
		o.MaxStreams = 256
	}
	if o.MaxFlows == 0 {
		o.MaxFlows = 256
	}
	if o.MaxStreams < 4 || o.MaxStreams > 512 || o.MaxFlows < 1 || o.MaxFlows > 4096 {
		return o, invalid()
	}
	for _, v := range []struct{ s, d string }{{o.ConnectTimeout, "30s"}, {o.HealthTimeout, "7s"}, {o.FallbackDelay, "1s"}, {o.IdleTimeout, "10m"}, {o.UDPIdleTimeout, "120s"}} {
		if _, e := Duration(v.s, v.d); e != nil {
			return o, e
		}
	}
	return o, nil
}
func (Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Key: Key(), ABI: 1, Roles: ports.Roles{Inbound: true, Outbound: true}, CredentialKinds: []access.CredentialKind{access.UsernamePassword}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "Independent TrustTunnel 1.0; H2/H3; ICMP qualification and fingerprint parity not claimed"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{Transport: ports.TransportCapabilities{TCP: true, UDPTransport: session.H3Enabled(), UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Identity: ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; runtime generation"}, Security: ports.SecurityCapabilities{TLS: true}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}}
}
func (Module) ValidateCredential(c access.Credential) error {
	if c.Validate() != nil || c.State != "active" || c.Kind != access.UsernamePassword {
		return invalid()
	}
	p, ok := c.Payload.(access.UsernamePasswordPayload)
	if !ok || !wire.Credentials(p.Username.Reveal(), p.Password.Reveal()) {
		return invalid()
	}
	return nil
}
func (Module) ValidateInbound(i access.Inbound) error {
	if i.Validate() != nil || i.Protocol != Key() || i.Engine != "native" || !i.Enabled || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	s, e := Decode(i.Settings.Data)
	if e != nil {
		return e
	}
	if s.Mode != "http2" && !session.H3Enabled() {
		return identity.Err(identity.NotImplemented, "TrustTunnel HTTP/3 requires with_quic")
	}
	count := 1
	if s.Mode == "auto" {
		count = 2
	}
	if len(i.Listeners) != count {
		return invalid()
	}
	seen := map[string]bool{}
	for _, l := range i.Listeners {
		if seen[l.Transport] || l.Endpoint != i.Listeners[0].Endpoint {
			return invalid()
		}
		seen[l.Transport] = true
	}
	if s.Mode == "auto" {
		if !seen["tcp"] || !seen["udp"] {
			return invalid()
		}
	} else if !seen[Carrier(s.Mode)] {
		return invalid()
	}
	return nil
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if e := m.ValidateInbound(in.Inbound); e != nil {
		return in, e
	}
	if len(in.Bindings) != len(in.Credentials) || len(in.Bindings) > 128 {
		return in, invalid()
	}
	ids := map[identity.ID]bool{}
	users := map[string]bool{}
	for i, b := range in.Bindings {
		c := in.Credentials[i]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil {
			return in, invalid()
		}
		p := c.Payload.(access.UsernamePasswordPayload)
		u := p.Username.Reveal()
		if users[u] {
			return in, invalid()
		}
		users[u] = true
		ids[b.ID] = true
	}
	return in, nil
}
func (m Module) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, e := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}}); e != nil {
		return clientprofile.Profile{}, e
	}
	s, _ := Decode(b.Inbound.Settings.Data)
	options, _ := json.Marshal(ClientOptions{Mode: s.Mode})
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, TLS: clientprofile.TLS{Enabled: true, ServerName: s.TLS.ServerName, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}, Transport: clientprofile.Transport{Kind: Carrier(s.Mode)}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: options}, Metadata: identity.Metadata{}}
	return p, p.Validate()
}
func ValidateClient(n client.RemoteNode, c access.Credential) error {
	if clientconfig.Ownership(n, c) != nil || (Module{}).ValidateCredential(c) != nil || n.Protocol != Key() || n.Security.Kind != "tls" {
		return invalid()
	}
	o, e := DecodeClient(n.Options.Data)
	if e != nil {
		return e
	}
	if n.Transport.Kind != Carrier(o.Mode) || n.Transport.Path != "" || n.Transport.Host != "" || len(n.Transport.Headers) != 0 || n.Transport.XHTTP != nil || n.Transport.FinalMask != nil || n.Transport.MKCP != nil || n.Transport.Hysteria != nil || n.Transport.ServiceName != "" {
		return invalid()
	}
	if len(n.Security.TLS.ALPN) > 0 {
		expected := "h2"
		if o.Mode == "http3" {
			expected = "h3"
		}
		if o.Mode == "auto" || len(n.Security.TLS.ALPN) != 1 || n.Security.TLS.ALPN[0] != expected {
			return invalid()
		}
	}
	if o.Mode != "http2" && !session.H3Enabled() {
		return identity.Err(identity.NotImplemented, "TrustTunnel HTTP/3 requires with_quic")
	}
	return nil
}
func Address(e access.Endpoint) string { return net.JoinHostPort(e.Host, fmt.Sprint(e.Port)) }
