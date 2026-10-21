// Package client owns committed client intent, independent of runtime engines.
package client

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	streamcfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"net/netip"
)

const Direct identity.ID = "direct"

type Transport = streamcfg.Config
type Security struct {
	Kind string           `json:"kind"`
	TLS  access.ClientTLS `json:"tls"`
}

// Options are bounded and adapter-validated. Secrets have a separate reference.
type Options struct {
	Schema int             `json:"schema_version"`
	Data   json.RawMessage `json:"data"`
}
type RemoteNode struct {
	Provenance   provider.Provenance `json:"provenance,omitzero"`
	Tags         []string            `json:"tags,omitempty"`
	Disabled     bool                `json:"disabled,omitempty"`
	State        string              `json:"state,omitempty"`
	ID           identity.ID         `json:"id"`
	Name         string              `json:"name"`
	Protocol     access.ProtocolKey  `json:"protocol"`
	Endpoint     access.Endpoint     `json:"endpoint"`
	CredentialID identity.ID         `json:"credential_id"`
	Transport    Transport           `json:"transport"`
	Security     Security            `json:"security"`
	Options      Options             `json:"options"`
	Metadata     identity.Metadata   `json:"metadata"`
}

func (n RemoteNode) Validate() error {
	if n.Provenance.Validate() != nil || len(n.Tags) > 32 {
		return invalid()
	}
	seen := map[string]bool{}
	for _, t := range n.Tags {
		if !identity.Label(t, 64) || seen[t] {
			return invalid()
		}
		seen[t] = true
	}
	switch n.State {
	case "", "active", "stale", "invalid", "unavailable":
	default:
		return invalid()
	}
	for _, id := range []identity.ID{n.ID, n.CredentialID} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if !identity.Label(n.Name, 128) {
		return invalid()
	}
	if err := n.Protocol.Validate(); err != nil {
		return err
	}
	if err := n.Endpoint.Validate(); err != nil {
		return err
	}
	if n.Transport.Kind == "" || n.Transport.ValidateClient() != nil || n.Transport.ValidateALPN(n.Security.TLS.ALPN) != nil || n.Security.TLS.Validate(n.Security.Kind) != nil || n.Options.Schema != 1 || len(n.Options.Data) > 16384 || !json.Valid(n.Options.Data) {
		return invalid()
	}
	if n.Transport.Kind == "hysteria" && n.Transport.ValidatePair(n.Protocol.Protocol, n.Security.Kind) != nil {
		return invalid()
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(n.Options.Data, &object) != nil || object == nil {
		return invalid()
	}
	return n.Metadata.Validate()
}

type Outbound struct {
	ProviderID identity.ID  `json:"provider_id,omitempty"`
	ID         identity.ID  `json:"id"`
	Name       string       `json:"name"`
	Kind       string       `json:"kind"`
	NodeID     *identity.ID `json:"node_id,omitempty"`
	Engine     string       `json:"engine,omitempty"`
}

func (o Outbound) Validate() error {
	if o.ProviderID != "" && (o.ProviderID.Validate() != nil || o.Kind != "proxy") {
		return invalid()
	}
	if !identity.Label(o.Name, 128) {
		return invalid()
	}
	if o.Kind == "direct" {
		if o.ID != Direct || o.NodeID != nil || o.Engine != "" {
			return invalid()
		}
		return nil
	}
	if o.Kind != "proxy" || o.ID == Direct || o.ID.Validate() != nil || o.NodeID == nil || o.NodeID.Validate() != nil || !identity.Label(o.Engine, 64) {
		return invalid()
	}
	return nil
}

type LocalInbound struct {
	Tunnel           *TunnelSettings  `json:"tunnel,omitempty"`
	Sniffing         *SniffingPolicy  `json:"sniffing,omitempty"`
	AllowLAN         bool             `json:"allow_lan,omitempty"`
	Auth             bool             `json:"auth,omitempty"`
	Bindings         []access.Binding `json:"bindings,omitempty"`
	TUN              *TUNSettings     `json:"tun,omitempty"`
	ID               identity.ID      `json:"id"`
	Name             string           `json:"name"`
	Kind             string           `json:"kind"`
	Listen           access.Endpoint  `json:"listen,omitzero"`
	SelectedOutbound identity.ID      `json:"selected_outbound,omitempty"`
}

func (i LocalInbound) Validate() error {
	if i.ID.Validate() != nil || !identity.Label(i.Name, 128) {
		return invalid()
	}
	if i.SelectedOutbound != "" && ValidateOutboundID(i.SelectedOutbound) != nil {
		return invalid()
	}
	if i.Kind == "tunnel" {
		return i.validateTunnel()
	}
	if i.Tunnel != nil || i.Sniffing != nil {
		return identity.Err(identity.Invalid, "tunnel and sniffing settings require kind tunnel")
	}
	if i.Kind == "tun" {
		if i.TUN == nil || i.Listen != (access.Endpoint{}) || i.Auth || i.AllowLAN || len(i.Bindings) > 0 {
			return invalid()
		}
		return i.TUN.Validate()
	}
	if i.TUN != nil || i.Kind != "socks5" && i.Kind != "http" && i.Kind != "mixed" {
		return invalid()
	}
	if err := i.Listen.Validate(); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(i.Listen.Host)
	if err != nil || !ip.IsLoopback() && !i.AllowLAN {
		return identity.Err(identity.Invalid, "local proxy requires loopback or explicit allow_lan")
	}
	if len(i.Bindings) > 128 {
		return invalid()
	}
	seen, accounts := map[identity.ID]bool{}, map[identity.ID]bool{}
	for _, b := range i.Bindings {
		if b.Validate() != nil || b.InboundID != i.ID || b.PolicyOverrideID != nil || seen[b.ID] || accounts[b.AccountID] {
			return invalid()
		}
		seen[b.ID] = true
		accounts[b.AccountID] = true
	}
	if i.SelectedOutbound != "" {
		return ValidateOutboundID(i.SelectedOutbound)
	}
	return nil
}
func (i *LocalInbound) Defaults() {
	if i.Kind != "tun" && i.Listen.Host == "" {
		i.Listen.Host = "127.0.0.1"
	}
	if i.Kind == "" {
		i.Kind = "socks5"
	}
}
func ValidateOutboundID(id identity.ID) error {
	if id == Direct {
		return nil
	}
	return id.Validate()
}

type Route struct {
	DefaultOutbound identity.ID `json:"default_outbound"`
}
type ProfileState struct {
	Management    provider.State       `json:"management"`
	Revision      identity.Revision    `json:"revision"`
	Enabled       bool                 `json:"enabled"`
	Nodes         []RemoteNode         `json:"nodes"`
	Outbounds     []Outbound           `json:"outbounds"`
	LocalInbounds []LocalInbound       `json:"local_inbounds"`
	Route         Route                `json:"route"`
	Network       networkpolicy.Config `json:"network"`
}

func Empty() ProfileState {
	return ProfileState{Nodes: []RemoteNode{}, Outbounds: []Outbound{{ID: Direct, Name: "DIRECT", Kind: "direct"}}, LocalInbounds: []LocalInbound{}, Route: Route{DefaultOutbound: Direct}, Enabled: true}
}
func (s ProfileState) Validate() error {
	if s.Management.Validate() != nil {
		return invalid()
	}
	providers := map[identity.ID]provider.Provider{}
	for _, p := range s.Management.Providers {
		providers[p.ID] = p
	}
	if s.Revision < 0 || len(s.Nodes) > 128 || len(s.Outbounds) > 129 || len(s.LocalInbounds) > 32 {
		return invalid()
	}
	nodes := map[identity.ID]bool{}
	nodeOwners := map[identity.ID]identity.ID{}
	creds := map[identity.ID]bool{}
	for _, n := range s.Nodes {
		if n.Provenance.ProviderID != "" && providers[n.Provenance.ProviderID].Kind != "proxy" {
			return invalid()
		}
		if err := n.Validate(); err != nil {
			return err
		}
		if nodes[n.ID] || creds[n.CredentialID] {
			return invalid()
		}
		nodes[n.ID] = true
		nodeOwners[n.ID] = n.Provenance.ProviderID
		creds[n.CredentialID] = true
	}
	out := map[identity.ID]bool{}
	for _, o := range s.Outbounds {
		if o.ProviderID != "" && providers[o.ProviderID].Kind != "proxy" {
			return invalid()
		}
		if err := o.Validate(); err != nil {
			return err
		}
		if o.ProviderID != "" && (o.NodeID == nil || nodeOwners[*o.NodeID] != o.ProviderID) {
			return invalid()
		}
		if out[o.ID] || o.NodeID != nil && !nodes[*o.NodeID] {
			return invalid()
		}
		out[o.ID] = true
	}
	if !out[Direct] || !out[s.Route.DefaultOutbound] {
		return identity.Err(identity.Invalid, "route references a missing outbound")
	}
	ids := map[identity.ID]bool{}
	listeners := map[access.Endpoint]bool{}
	tunNames := map[string]bool{}
	bindings := map[identity.ID]bool{}
	for _, i := range s.LocalInbounds {
		if err := i.Validate(); err != nil {
			return err
		}
		if ids[i.ID] || i.Kind != "tun" && listeners[i.Listen] || i.SelectedOutbound != "" && !out[i.SelectedOutbound] {
			return invalid()
		}
		ids[i.ID] = true
		for _, b := range i.Bindings {
			if bindings[b.ID] {
				return invalid()
			}
			bindings[b.ID] = true
		}
		if i.Kind == "tun" {
			if len(tunNames) != 0 || tunNames[i.TUN.Interface] {
				return identity.Err(identity.Invalid, "one owned TUN per client runtime")
			}
			tunNames[i.TUN.Interface] = true
			if i.TUN.DNSHijack && !s.Network.DNS.Enabled {
				return identity.Err(identity.Invalid, "DNS interception requires managed DNS")
			}
		} else {
			listeners[i.Listen] = true
		}
	}
	if e := s.Network.Validate(out, ids); e != nil {
		return e
	}
	if e := s.validateTunnelRoutes(); e != nil {
		return e
	}
	return s.ValidateProviderDependencies()
}

// Clone copies all mutable containers before publishing intent to a runtime.
func (s ProfileState) Clone() ProfileState {
	b, _ := json.Marshal(s)
	var c ProfileState
	_ = json.Unmarshal(b, &c)
	return c
}
func invalid() error { return identity.Err(identity.Invalid, "invalid client intent or reference") }
