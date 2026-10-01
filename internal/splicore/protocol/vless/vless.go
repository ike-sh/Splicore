package vless

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"strings"
)

type Module struct{ Security Security }

func (m Module) Metadata() ports.ProtocolMetadata {
	availability := ports.Compiled
	if m.Security == Reality && !RealityCompiled {
		availability = ports.NotCompiled
	}
	return ports.ProtocolMetadata{Key: Key(m.Security), ABI: 1, CredentialKinds: []access.CredentialKind{access.UUID}, Availability: availability, Qualification: "experimental", Provenance: "sing-box v1.14.1 / sing-vmess v0.2.8; TCP; UUID; XUDP; no flow; Vision deferred/unsupported; REALITY requires with_utls"}
}
func (m Module) Capabilities(c ports.CapabilityContext) ports.Capabilities {
	available := (c.Engine == "" || c.Engine == "native") && m.Metadata().Availability == ports.Compiled
	flows := []string{string(NoFlow)}
	support := ports.Unsupported
	mutation := ports.MutationUnavailable
	if available {
		support = ports.Native
		mutation = ports.Restart
	}
	return ports.Capabilities{Transport: ports.TransportCapabilities{Kinds: []string{"tcp"}, TCP: available, UDPPayload: available, IPv4: available, IPv6: available, DomainEndpoint: available}, Identity: ports.IdentityCapabilities{MultiUserNative: available, PerUserStats: available, AttributedPayload: support, NativeStats: support, StatsUnits: "authenticated routed payload bytes and sessions; runtime generation"}, Security: ports.SecurityCapabilities{TLS: available && m.Security != Plain, Reality: available && m.Security == Reality, Vision: false, Flows: flows}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: mutation, Listener: ports.MutationUnavailable}, Clients: []ports.ClientCompatibility{}}
}
func (m Module) ValidateInbound(i access.Inbound) error {
	if err := i.Validate(); err != nil {
		return err
	}
	s, err := Decode(i.Settings.Data)
	if err != nil {
		return err
	}
	if i.Protocol != Key(m.Security) || s.Security != m.Security || !i.Enabled || len(i.Listeners) != 1 || i.Listeners[0].Transport != "tcp" || len(i.DisplayEndpoints) != 1 {
		return invalid()
	}
	// Engine-neutral protocol validation permits future registered implementations.
	return nil
}
func (Module) ValidateCredential(c access.Credential) error {
	p, ok := c.Payload.(access.UUIDPayload)
	if !ok || c.Validate() != nil || c.State != "active" || c.Kind != access.UUID || ValidateUUID(p.UUID) != nil {
		return invalid()
	}
	return nil
}
func (m Module) validateUsers(in ports.RuntimeIntent) error {
	if len(in.Bindings) != len(in.Credentials) || len(in.Bindings) > 16 {
		return invalid()
	}
	ids, uuids := map[identity.ID]bool{}, map[string]bool{}
	for n, b := range in.Bindings {
		c := in.Credentials[n]
		if b.Validate() != nil || !b.Enabled || ids[b.ID] || b.InboundID != in.Inbound.ID || b.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != b.AccountID || m.ValidateCredential(c) != nil {
			return invalid()
		}
		id := strings.ToLower(c.Payload.(access.UUIDPayload).UUID.Reveal())
		if uuids[id] {
			return invalid()
		}
		uuids[id] = true
		ids[b.ID] = true
	}
	return nil
}
func (m Module) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	// This gate also protects callers that bypass creation/inbound validation.
	if _, err := Decode(in.Inbound.Settings.Data); err != nil {
		return in, err
	}
	if err := m.ValidateInbound(in.Inbound); err != nil {
		return in, err
	}
	if err := m.validateUsers(in); err != nil {
		return in, err
	}
	if m.Security == Reality {
		if len(in.ServerCredentials) != 1 {
			return in, invalid()
		}
		c := in.ServerCredentials[0]
		p, ok := c.Payload.(access.PrivateKeyPayload)
		if !ok || c.Validate() != nil || c.State != "active" || c.OwnerInboundID == nil || *c.OwnerInboundID != in.Inbound.ID {
			return in, invalid()
		}
		pub, err := DerivePublicKey(p)
		s, _ := Decode(in.Inbound.Settings.Data)
		if err != nil || pub != s.Reality.PublicKey {
			return in, invalid()
		}
	} else if len(in.ServerCredentials) != 0 {
		return in, invalid()
	}
	return in, nil
}
func (m Module) BuildClientProfile(_ context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if err := m.ValidateInbound(b.Inbound); err != nil {
		return clientprofile.Profile{}, err
	}
	if err := m.validateUsers(ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding}, Credentials: []access.Credential{b.Credential}}); err != nil {
		return clientprofile.Profile{}, err
	}
	s, _ := Decode(b.Inbound.Settings.Data)
	p := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key(s.Security), Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: clientOptions(s)}, Metadata: identity.Metadata{}}
	if s.Security == TLS {
		p.TLS = clientprofile.TLS{Enabled: true, ServerName: s.TLS.ServerName, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}
	}
	if s.Security == Reality {
		p.TLS = clientprofile.TLS{Enabled: true, ServerName: s.Reality.ServerName, Trust: "reality", RealityPublicKey: string(s.Reality.PublicKey), RealityShortID: string(s.Reality.ShortIDs[0])}
	}
	return p, p.Validate()
}
