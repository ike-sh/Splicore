// Package naive owns first-class Naive proxy intent; carriers are not shared transports.
package naive

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/protocol/naive/backend"
	"net/http"
	"strings"
	"time"
)

type Module struct{}

func Key() access.ProtocolKey {
	return access.ProtocolKey{Protocol: "naive", WireVersion: "connect", FeatureProfile: "base"}
}
func invalid() error { return identity.Err(identity.Invalid, "invalid Naive settings or credential") }

type Settings struct {
	TLS            tlsconfig.Settings `json:"tls"`
	Mode           string             `json:"mode"`
	MaxStreams     int                `json:"max_streams,omitempty"`
	ConnectTimeout string             `json:"connect_timeout,omitempty"`
	IdleTimeout    string             `json:"idle_timeout,omitempty"`
}
type ClientOptions struct {
	Mode              string            `json:"mode"`
	Padding           string            `json:"padding,omitempty"`
	ExtraHeaders      map[string]string `json:"extra_headers,omitempty"`
	MaxConnections    int               `json:"max_connections,omitempty"`
	MaxStreams        int               `json:"max_streams,omitempty"`
	ConnectTimeout    string            `json:"connect_timeout,omitempty"`
	TunnelTimeout     string            `json:"tunnel_timeout,omitempty"`
	IdleTimeout       string            `json:"idle_timeout,omitempty"`
	CongestionControl string            `json:"congestion_control,omitempty"`
}

func (Settings) Format(s fmt.State, _ rune)      { _, _ = s.Write([]byte("NaiveSettings{[REDACTED]}")) }
func (ClientOptions) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("NaiveOptions{[REDACTED]}")) }
func fields(b []byte, allowed ...string) error {
	var object map[string]json.RawMessage
	if len(b) > 16384 || json.Unmarshal(b, &object) != nil || object == nil {
		return invalid()
	}
	for key, value := range object {
		known := false
		for _, name := range allowed {
			known = known || key == name
		}
		if !known {
			return invalid()
		}
		if strings.TrimSpace(string(value)) == "null" {
			return invalid()
		}
	}
	return nil
}
func Duration(value, defaultValue string) (time.Duration, error) {
	if value == "" {
		value = defaultValue
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < time.Second || d > 24*time.Hour {
		return 0, invalid()
	}
	return d, nil
}
func mode(value string) bool { return value == "https" || value == "quic" }
func Carrier(value string) string {
	if value == "quic" {
		return "quic"
	}
	return "tcp"
}
func ALPN(value string) string {
	if value == "quic" {
		return "h3"
	}
	return "h2"
}
func Decode(b []byte) (Settings, error) {
	var s Settings
	if fields(b, "tls", "mode", "max_streams", "connect_timeout", "idle_timeout") != nil || jsonstrict.Decode(b, &s) != nil || !mode(s.Mode) || tlsconfig.Validate(s.TLS) != nil {
		return s, invalid()
	}
	if s.MaxStreams == 0 {
		s.MaxStreams = 512
	}
	if s.MaxStreams < 1 || s.MaxStreams > 512 {
		return s, invalid()
	}
	if _, err := Duration(s.ConnectTimeout, "5s"); err != nil {
		return s, err
	}
	if _, err := Duration(s.IdleTimeout, "10m"); err != nil {
		return s, err
	}
	return s, nil
}
func DecodeClient(b []byte) (ClientOptions, error) {
	var o ClientOptions
	if fields(b, "mode", "padding", "extra_headers", "max_connections", "max_streams", "connect_timeout", "tunnel_timeout", "idle_timeout", "congestion_control") != nil || jsonstrict.Decode(b, &o) != nil || !mode(o.Mode) {
		return o, invalid()
	}
	if o.Padding == "" {
		o.Padding = "auto"
	}
	if o.Padding != "auto" && o.Padding != "enabled" && o.Padding != "off" {
		return o, invalid()
	}
	if o.MaxConnections == 0 {
		o.MaxConnections = 1
	}
	if o.MaxStreams == 0 {
		o.MaxStreams = 128
	}
	if o.MaxConnections < 1 || o.MaxConnections > 4 || o.MaxStreams < 1 || o.MaxStreams > 512 {
		return o, invalid()
	}
	if o.CongestionControl != "" && (o.Mode != "quic" || o.CongestionControl != "cubic") {
		return o, invalid()
	}
	if backend.ValidateHeaders(o.Headers()) != nil {
		return o, invalid()
	}
	for _, value := range []struct{ value, defaultValue string }{{o.ConnectTimeout, "5s"}, {o.TunnelTimeout, "30m"}, {o.IdleTimeout, "10m"}} {
		if _, err := Duration(value.value, value.defaultValue); err != nil {
			return o, err
		}
	}
	return o, nil
}
func (o ClientOptions) Headers() http.Header {
	h := http.Header{}
	for name, value := range o.ExtraHeaders {
		h[name] = []string{value}
	}
	return h
}
func (m Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Key: Key(), ABI: 1, Roles: ports.Roles{Inbound: true, Outbound: true}, CredentialKinds: []access.CredentialKind{access.UsernamePassword}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "Independent native Naive CONNECT/padding; generic Go H2/H3; Chromium fingerprint parity not claimed"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{
		Transport: ports.TransportCapabilities{TCP: true, UDPTransport: true, UDPPayload: false, IPv4: true, IPv6: true, DomainEndpoint: true},
		Identity:  ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; runtime generation"},
		Security:  ports.SecurityCapabilities{TLS: true}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported},
		Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}}
}
func (Module) ValidateCredential(c access.Credential) error {
	if c.Validate() != nil || c.State != "active" || c.Kind != access.UsernamePassword {
		return invalid()
	}
	if _, err := proxy.Pair(c); err != nil {
		return invalid()
	}
	return nil
}
func (Module) ValidateInbound(i access.Inbound) error {
	if i.Validate() != nil || i.Protocol != Key() || i.Engine != "native" || !i.Enabled || len(i.Listeners) != 1 || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	s, err := Decode(i.Settings.Data)
	if err != nil {
		return err
	}
	transport := "tcp"
	if s.Mode == "quic" {
		transport = "udp"
		if !backend.H3Enabled() {
			return identity.Err(identity.NotImplemented, "Naive HTTP/3 requires with_quic")
		}
	}
	if i.Listeners[0].Transport != transport {
		return invalid()
	}
	return nil
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if err := m.ValidateInbound(in.Inbound); err != nil {
		return in, err
	}
	if len(in.Bindings) != len(in.Credentials) || len(in.Bindings) > 128 {
		return in, invalid()
	}
	ids := map[identity.ID]bool{}
	usernames := map[string]bool{}
	for index, b := range in.Bindings {
		cred := in.Credentials[index]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != cred.ID || cred.OwnerAccountID == nil || *cred.OwnerAccountID != b.AccountID || m.ValidateCredential(cred) != nil {
			return in, invalid()
		}
		pair, _ := proxy.Pair(cred)
		if usernames[pair.Username] {
			return in, invalid()
		}
		usernames[pair.Username] = true
		ids[b.ID] = true
	}
	return in, nil
}
func (m Module) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, err := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}}); err != nil {
		return clientprofile.Profile{}, err
	}
	s, _ := Decode(b.Inbound.Settings.Data)
	options, _ := json.Marshal(ClientOptions{Mode: s.Mode, Padding: "auto"})
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload,
		TLS:       clientprofile.TLS{Enabled: true, ServerName: s.TLS.ServerName, ALPN: []string{ALPN(s.Mode)}, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate},
		Transport: clientprofile.Transport{Kind: Carrier(s.Mode)}, Options: access.Settings{Schema: 1, Data: options}, Metadata: identity.Metadata{}}
	return p, p.Validate()
}
func ValidateClient(n client.RemoteNode, c access.Credential) error {
	if clientconfig.Ownership(n, c) != nil || (Module{}).ValidateCredential(c) != nil || n.Protocol != Key() || n.Security.Kind != "tls" {
		return invalid()
	}
	o, err := DecodeClient(n.Options.Data)
	if err != nil {
		return err
	}
	if n.Transport.Kind != Carrier(o.Mode) || n.Transport.Path != "" || n.Transport.Host != "" || len(n.Transport.Headers) != 0 || n.Transport.XHTTP != nil || n.Transport.FinalMask != nil || n.Transport.ServiceName != "" {
		return invalid()
	}
	if len(n.Security.TLS.ALPN) > 0 && (len(n.Security.TLS.ALPN) != 1 || n.Security.TLS.ALPN[0] != ALPN(o.Mode)) {
		return invalid()
	}
	if o.Mode == "quic" && !backend.H3Enabled() {
		return identity.Err(identity.NotImplemented, "Naive HTTP/3 requires with_quic")
	}
	return nil
}
