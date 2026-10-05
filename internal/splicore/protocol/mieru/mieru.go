// Package mieru owns the bounded canonical contract, not upstream wire code.
package mieru

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/credential"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	"github.com/sagernet/sing-box/internal/splicore/ports"
)

const ReferenceVersion = "3.38.0"
const ReferenceCommit = "b961978c3be9dd26b94158487c760858e19d1db2"

type Module struct{}
type Settings struct {
	Transport string `json:"transport"`
	MTU       int    `json:"mtu"`
	Multiplex string `json:"multiplex"`
}

func Key() access.ProtocolKey {
	return access.ProtocolKey{Protocol: "mieru", WireVersion: "2", FeatureProfile: "base"}
}
func invalid() error { return identity.Err(identity.Invalid, "invalid Mieru settings or credentials") }
func Decode(data []byte) (Settings, error) {
	var s Settings
	if len(data) > 16384 || jsonstrict.Decode(data, &s) != nil {
		return s, invalid()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return s, invalid()
	}
	for _, field := range fields {
		if string(field) == "null" {
			return s, invalid()
		}
	}
	if s.MTU == 0 {
		s.MTU = 1500
	}
	if _, present := fields["multiplex"]; !present {
		s.Multiplex = "default"
	}
	if s.Transport != "tcp" && s.Transport != "udp" || s.MTU < 1280 || s.MTU > 1500 {
		return s, invalid()
	}
	switch s.Multiplex {
	case "default", "off", "low", "middle", "high":
	default:
		return s, invalid()
	}
	return s, nil
}
func ValidateUsername(v secret.Value) error {
	if !identity.Label(v.Reveal(), 64) || strings.ContainsAny(v.Reveal(), " \t\r\n") {
		return invalid()
	}
	return nil
}
func ValidatePassword(v secret.Value) error {
	if credential.ValidatePassword(v) != nil || len(v.Reveal()) > 64 {
		return invalid()
	}
	return nil
}
func (Module) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Roles: ports.Roles{Inbound: true, Outbound: true}, Key: Key(), ABI: 1, CredentialKinds: []access.CredentialKind{access.UsernamePassword}, Availability: ports.Compiled, Qualification: "experimental", Provenance: "official Mieru v" + ReferenceVersion + " / " + ReferenceCommit + "; embedded server API; default traffic pattern"}
}
func (Module) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{Transport: ports.TransportCapabilities{Kinds: []string{"tcp", "udp"}, TCP: true, UDPTransport: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Identity: ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native, StatsUnits: "authenticated payload bytes; routed sessions; runtime generation; upstream global counters are reference only"}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}, Clients: []ports.ClientCompatibility{{Format: ports.Mieru, Client: "mieru", Version: ReferenceVersion, Evidence: "docs/reports/PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md"}, {Format: ports.Mihomo, Client: "mihomo", Version: "1.19.30", Evidence: "docs/reports/PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md"}}}
}
func (Module) ValidateInbound(i access.Inbound) error {
	if i.Validate() != nil {
		return invalid()
	}
	s, e := Decode(i.Settings.Data)
	if e != nil {
		return e
	}
	if len(i.Listeners) != 1 {
		return invalid()
	}
	ip, err := netip.ParseAddr(i.Listeners[0].Endpoint.Host)
	if err != nil || ip.Zone() != "" {
		return invalid()
	}
	if i.Protocol != Key() || i.Engine != "native" || !i.Enabled || len(i.Listeners) != 1 || i.Listeners[0].Transport != s.Transport || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	return nil
}
func (Module) ValidateCredential(c access.Credential) error {
	p, ok := c.Payload.(access.UsernamePasswordPayload)
	if !ok || c.Validate() != nil || c.Kind != access.UsernamePassword || c.State != "active" || ValidateUsername(p.Username) != nil || ValidatePassword(p.Password) != nil {
		return invalid()
	}
	return nil
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if e := m.ValidateInbound(in.Inbound); e != nil {
		return in, e
	}
	if len(in.Bindings) < 1 || len(in.Bindings) > 16 || len(in.Bindings) != len(in.Credentials) {
		return in, invalid()
	}
	ids, names := map[identity.ID]bool{}, map[string]bool{}
	for n, b := range in.Bindings {
		c := in.Credentials[n]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil {
			return in, invalid()
		}
		ids[b.ID] = true
		name := c.Payload.(access.UsernamePasswordPayload).Username.Reveal()
		if names[name] {
			return in, invalid()
		}
		names[name] = true
	}
	return in, nil
}
func (m Module) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, e := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}}); e != nil {
		return clientprofile.Profile{}, e
	}
	s, _ := Decode(b.Inbound.Settings.Data)
	data, _ := json.Marshal(s)
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, Transport: clientprofile.Transport{Kind: s.Transport}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: data}, Metadata: identity.Metadata{}}
	return p, p.Validate()
}
