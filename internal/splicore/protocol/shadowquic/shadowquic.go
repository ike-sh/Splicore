// Package shadowquic owns native ShadowQUIC intent, separately from its QUIC carrier.
package shadowquic

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/protocol/shadowquic/session"
)

type (
	Module   struct{}
	Settings struct {
		session.Limits
		ServerName string          `json:"server_name"`
		Camouflage access.Endpoint `json:"camouflage_endpoint"`
	}
)

type ClientOptions struct {
	session.Limits
	UDPOverStream bool `json:"udp_over_stream,omitempty"`
}

func (Settings) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("ShadowQUICSettings{[REDACTED]}")) }

func Key() access.ProtocolKey {
	return access.ProtocolKey{Protocol: "shadowquic", WireVersion: "unversioned", FeatureProfile: "jls3"}
}

func invalid() error {
	return identity.Err(identity.Invalid, "invalid ShadowQUIC configuration or credential")
}

func exact(b []byte, server bool) error {
	var obj map[string]json.RawMessage
	if len(b) > 16384 || jsonstrict.Decode(b, &obj) != nil || obj == nil {
		return invalid()
	}
	allowed := map[string]bool{"max_streams": true, "max_udp_flows": true, "handshake_timeout": true, "idle_timeout": true, "keepalive": true, "udp_idle_timeout": true}
	if server {
		allowed["server_name"], allowed["camouflage_endpoint"], allowed["max_connections"] = true, true, true
	} else {
		allowed["udp_over_stream"] = true
	}
	for k, v := range obj {
		if !allowed[k] || strings.TrimSpace(string(v)) == "null" {
			return invalid()
		}
	}
	return nil
}

func Decode(b []byte) (Settings, error) {
	var s Settings
	if exact(b, true) != nil || jsonstrict.Decode(b, &s) != nil || s.Limits.Validate() != nil || s.Camouflage.Validate() != nil || !ValidServerName(s.ServerName) {
		return s, invalid()
	}
	return s, nil
}

func DecodeClient(b []byte) (ClientOptions, error) {
	var o ClientOptions
	if exact(b, false) != nil || jsonstrict.Decode(b, &o) != nil || o.Limits.Validate() != nil {
		return o, invalid()
	}
	return o, nil
}

func Pair(p access.Payload) (access.UsernamePasswordPayload, error) {
	u, ok := p.(access.UsernamePasswordPayload)
	if !ok || !utf8.ValidString(u.Username.Reveal()) || u.Username.Empty() || len(u.Username.Reveal()) > 255 || strings.IndexFunc(u.Username.Reveal(), unicode.IsControl) >= 0 || credential.ValidatePassword(u.Password) != nil {
		return u, invalid()
	}
	return u, nil
}

func (Module) Metadata() ports.ProtocolMetadata {
	availability := ports.Compiled
	if !session.Enabled() {
		availability = ports.NotCompiled
	}
	return ports.ProtocolMetadata{Key: Key(), ABI: 1, Roles: ports.Roles{Inbound: true, Outbound: true}, CredentialKinds: []access.CredentialKind{access.UsernamePassword}, Availability: availability, Qualification: "experimental", Provenance: "Splicore-owned ShadowQUIC grammar; upstream v0.4.7; independent JLS v3 libraries; TCP, UDP DATAGRAM and CMD4 streams; 0-RTT disabled"}
}

func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{Transport: ports.TransportCapabilities{TCP: true, UDPTransport: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Security: ports.SecurityCapabilities{TLS: true}, Identity: ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; runtime generation"}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}}
}

func (Module) ValidateCredential(c access.Credential) error {
	if c.Validate() != nil || c.Kind != access.UsernamePassword || c.State != "active" {
		return invalid()
	}
	_, err := Pair(c.Payload)
	return err
}

func (Module) ValidateInbound(i access.Inbound) error {
	if i.Validate() != nil || i.Protocol != Key() || i.Engine != "native" || !i.Enabled || len(i.Listeners) != 1 || i.Listeners[0].Transport != "udp" || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	if !session.Enabled() {
		return identity.Err(identity.NotImplemented, "ShadowQUIC requires with_quic")
	}
	_, err := Decode(i.Settings.Data)
	return err
}

func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if err := m.ValidateInbound(in.Inbound); err != nil {
		return in, err
	}
	if len(in.Bindings) != len(in.Credentials) || len(in.Bindings) > 128 {
		return in, invalid()
	}
	ids, users := map[identity.ID]bool{}, map[string]bool{}
	for i, b := range in.Bindings {
		c := in.Credentials[i]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil {
			return in, invalid()
		}
		p, _ := Pair(c.Payload)
		u := p.Username.Reveal()
		if users[u] {
			return in, invalid()
		}
		ids[b.ID], users[u] = true, true
	}
	return in, nil
}

func (m Module) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, err := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}}); err != nil {
		return clientprofile.Profile{}, err
	}
	s, _ := Decode(b.Inbound.Settings.Data)
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, TLS: clientprofile.TLS{Enabled: true, ServerName: s.ServerName, ALPN: []string{"h3"}, Trust: "jls"}, Transport: clientprofile.Transport{Kind: "quic"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: []byte(`{}`)}, Metadata: identity.Metadata{}}
	return p, p.Validate()
}

func ValidateClient(n client.RemoteNode, c access.Credential) error {
	if clientconfig.Ownership(n, c) != nil || n.Protocol != Key() || n.Security.Kind != "jls" || n.Transport.Kind != "quic" || (Module{}).ValidateCredential(c) != nil {
		return invalid()
	}
	if n.Transport.Hysteria != nil || n.Transport.MKCP != nil || n.Transport.XHTTP != nil || n.Transport.FinalMask != nil || n.Transport.Path != "" || n.Transport.Host != "" || len(n.Transport.Headers) != 0 || n.Transport.ServiceName != "" || !ValidServerName(n.Security.TLS.ServerName) {
		return invalid()
	}
	if !session.Enabled() {
		return identity.Err(identity.NotImplemented, "ShadowQUIC requires with_quic")
	}
	_, err := DecodeClient(n.Options.Data)
	return err
}

func Address(e access.Endpoint) string { return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))) }

// ValidServerName requires an explicit DNS SNI, never a URL, IP literal or wildcard.
func ValidServerName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
