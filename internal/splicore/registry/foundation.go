package registry

import (
	"context"
	"slices"

	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
)

// ProtocolPlaceholder declares identity only, never qualified runtime behavior.
type ProtocolPlaceholder struct{ Info ports.ProtocolMetadata }

func (p ProtocolPlaceholder) Metadata() ports.ProtocolMetadata {
	m := p.Info
	m.CredentialKinds = slices.Clone(m.CredentialKinds)
	return m
}

func (p ProtocolPlaceholder) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return UnavailableCapabilities()
}
func (p ProtocolPlaceholder) ValidateInbound(access.Inbound) error { return notImplemented() }
func (p ProtocolPlaceholder) ValidateCredential(c access.Credential) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if !slices.Contains(p.Info.CredentialKinds, c.Kind) {
		return identity.Err(identity.Invalid, "incompatible credential kind")
	}
	return notImplemented()
}

func (p ProtocolPlaceholder) BuildRuntime(context.Context, ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	return ports.RuntimeIntent{}, notImplemented()
}

func (p ProtocolPlaceholder) BuildClientProfile(context.Context, ports.AuthorizedBinding) (clientprofile.Profile, error) {
	return clientprofile.Profile{}, notImplemented()
}

type EnginePlaceholder struct{ Info ports.EngineMetadata }

func (e EnginePlaceholder) Metadata() ports.EngineMetadata {
	m := e.Info
	m.Protocols = slices.Clone(m.Protocols)
	return m
}
func (e EnginePlaceholder) Capabilities() ports.Capabilities   { return UnavailableCapabilities() }
func (e EnginePlaceholder) Supports(ports.RuntimeIntent) error { return notImplemented() }
func (e EnginePlaceholder) Compile(context.Context, ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	return nil, notImplemented()
}

type ExporterPlaceholder struct{ ID ports.Format }

func (e ExporterPlaceholder) Format() ports.Format { return e.ID }
func (e ExporterPlaceholder) Export(context.Context, clientprofile.Profile, ports.ExportTarget) ([]byte, error) {
	return nil, notImplemented()
}

func notImplemented() error {
	return identity.Err(identity.NotImplemented, "foundation extension has no runtime implementation")
}

func UnavailableCapabilities() ports.Capabilities {
	return ports.Capabilities{Identity: ports.IdentityCapabilities{AttributedPayload: ports.Unsupported, NativeStats: ports.Unsupported}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.MutationUnavailable, Listener: ports.MutationUnavailable}, Clients: []ports.ClientCompatibility{}}
}

func Foundation() (*Protocols, *Engines, *Exporters, error) {
	// Explicit compiled composition; no global init registration or plugin loader.
	p, err := NewProtocols(
		ProtocolPlaceholder{ports.ProtocolMetadata{Key: access.ProtocolKey{Protocol: "snell", WireVersion: "6", FeatureProfile: "base"}, ABI: 1, CredentialKinds: []access.CredentialKind{access.PSK}, Availability: ports.NotCompiled, Qualification: "unqualified", Provenance: "sing-box v1.14.1; adapter deferred"}},
		ProtocolPlaceholder{ports.ProtocolMetadata{Key: access.ProtocolKey{Protocol: "hysteria2", WireVersion: "2", FeatureProfile: "base"}, ABI: 1, CredentialKinds: []access.CredentialKind{access.PSK}, Availability: ports.NotCompiled, Qualification: "unqualified", Provenance: "sing-box v1.14.1; adapter deferred"}},
		ProtocolPlaceholder{ports.ProtocolMetadata{Key: access.ProtocolKey{Protocol: "tuic", WireVersion: "5", FeatureProfile: "base"}, ABI: 1, CredentialKinds: []access.CredentialKind{access.UUIDPassword}, Availability: ports.NotCompiled, Qualification: "unqualified", Provenance: "sing-box v1.14.1; adapter deferred"}},
		ProtocolPlaceholder{ports.ProtocolMetadata{Key: access.ProtocolKey{Protocol: "vless", WireVersion: "0", FeatureProfile: "base"}, ABI: 1, CredentialKinds: []access.CredentialKind{access.UUID}, Availability: ports.NotCompiled, Qualification: "unqualified", Provenance: "sing-box v1.14.1; adapter deferred"}},
	)
	if err != nil {
		return nil, nil, nil, err
	}
	e, err := NewEngines(EnginePlaceholder{ports.EngineMetadata{ID: "native", Availability: ports.Compiled, ABI: 1}})
	if err != nil {
		return nil, nil, nil, err
	}
	x, err := NewExporters(ExporterPlaceholder{ports.Mihomo}, ExporterPlaceholder{ports.SingBox}, ExporterPlaceholder{ports.Surge}, ExporterPlaceholder{ports.URI}, ExporterPlaceholder{ports.JSON})
	return p, e, x, err
}
