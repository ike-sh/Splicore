// Package client owns committed client intent, independent of runtime engines.
package client

import (
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"net/netip"
)

const Direct identity.ID = "direct"

type Transport struct {
	Kind string `json:"kind"`
}
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
	ID           identity.ID        `json:"id"`
	Name         string             `json:"name"`
	Protocol     access.ProtocolKey `json:"protocol"`
	Endpoint     access.Endpoint    `json:"endpoint"`
	CredentialID identity.ID        `json:"credential_id"`
	Transport    Transport          `json:"transport"`
	Security     Security           `json:"security"`
	Options      Options            `json:"options"`
	Metadata     identity.Metadata  `json:"metadata"`
}

func (n RemoteNode) Validate() error {
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
	if (n.Transport.Kind != "tcp" && n.Transport.Kind != "quic" && n.Transport.Kind != "udp") || n.Security.TLS.Validate(n.Security.Kind) != nil || n.Options.Schema != 1 || len(n.Options.Data) > 16384 || !json.Valid(n.Options.Data) {
		return invalid()
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(n.Options.Data, &object) != nil || object == nil {
		return invalid()
	}
	return n.Metadata.Validate()
}

type Outbound struct {
	ID     identity.ID  `json:"id"`
	Name   string       `json:"name"`
	Kind   string       `json:"kind"`
	NodeID *identity.ID `json:"node_id,omitempty"`
	Engine string       `json:"engine,omitempty"`
}

func (o Outbound) Validate() error {
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
	ID               identity.ID     `json:"id"`
	Name             string          `json:"name"`
	Kind             string          `json:"kind"`
	Listen           access.Endpoint `json:"listen"`
	SelectedOutbound identity.ID     `json:"selected_outbound,omitempty"`
}

func (i LocalInbound) Validate() error {
	if i.ID.Validate() != nil || !identity.Label(i.Name, 128) || i.Kind != "socks5" {
		return invalid()
	}
	if err := i.Listen.Validate(); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(i.Listen.Host)
	if err != nil || !ip.IsLoopback() {
		return identity.Err(identity.Invalid, "unauthenticated local SOCKS requires a loopback IP")
	}
	if i.SelectedOutbound != "" {
		return ValidateOutboundID(i.SelectedOutbound)
	}
	return nil
}
func (i *LocalInbound) Defaults() {
	if i.Listen.Host == "" {
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
	if s.Revision < 0 || len(s.Nodes) > 128 || len(s.Outbounds) > 129 || len(s.LocalInbounds) > 32 {
		return invalid()
	}
	nodes := map[identity.ID]bool{}
	creds := map[identity.ID]bool{}
	for _, n := range s.Nodes {
		if err := n.Validate(); err != nil {
			return err
		}
		if nodes[n.ID] || creds[n.CredentialID] {
			return invalid()
		}
		nodes[n.ID] = true
		creds[n.CredentialID] = true
	}
	out := map[identity.ID]bool{}
	for _, o := range s.Outbounds {
		if err := o.Validate(); err != nil {
			return err
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
	for _, i := range s.LocalInbounds {
		if err := i.Validate(); err != nil {
			return err
		}
		if ids[i.ID] || listeners[i.Listen] || i.SelectedOutbound != "" && !out[i.SelectedOutbound] {
			return invalid()
		}
		ids[i.ID] = true
		listeners[i.Listen] = true
	}
	return s.Network.Validate(out, ids)
}

// Clone copies all mutable containers before publishing intent to a runtime.
func (s ProfileState) Clone() ProfileState {
	b, _ := json.Marshal(s)
	var c ProfileState
	_ = json.Unmarshal(b, &c)
	return c
}
func invalid() error { return identity.Err(identity.Invalid, "invalid client intent or reference") }
