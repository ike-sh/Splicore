package clientruntime

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"sort"
)

type Observation struct {
	ID    identity.ID  `json:"id"`
	Stats TrafficStats `json:"stats"`
}
type OutboundHealth struct {
	ID         identity.ID  `json:"id"`
	Configured bool         `json:"configured"`
	Available  bool         `json:"available"`
	Active     bool         `json:"active"`
	LastError  string       `json:"last_error,omitempty"`
	Stats      TrafficStats `json:"stats"`
}
type SessionView struct {
	AccountID  identity.ID  `json:"account_id,omitempty"`
	ID         identity.ID  `json:"id"`
	InboundID  identity.ID  `json:"local_inbound_id"`
	OutboundID identity.ID  `json:"outbound_id,omitempty"`
	NodeID     identity.ID  `json:"node_id,omitempty"`
	Kind       string       `json:"kind"`
	Stats      TrafficStats `json:"stats"`
}
type Status struct {
	Accounts         []Observation              `json:"accounts"`
	ProxyInterfaces  []ports.OutboundCapability `json:"proxy_interfaces"`
	Underlay         underlay.Status            `json:"underlay"`
	HostCapabilities hostnetwork.Capabilities   `json:"host_capabilities"`
	Host             hostnetwork.Status         `json:"host_network"`
	Network          NetworkStatus              `json:"network_runtime"`
	State            client.ProfileState        `json:"state"`
	Health           string                     `json:"health"`
	LocalSOCKSTCP    bool                       `json:"local_socks_tcp"`
	LocalSOCKSUDP    string                     `json:"local_socks_udp"`
	OutboundAdapters []ports.OutboundCapability `json:"outbound_adapters"`
	LocalStats       []Observation              `json:"local_inbounds"`
	Outbounds        []OutboundHealth           `json:"outbounds"`
	Nodes            []Observation              `json:"nodes"`
	Sessions         []SessionView              `json:"sessions"`
	LastError        string                     `json:"last_error,omitempty"`
}

func (m *Manager) Status(state client.ProfileState, capabilities []ports.OutboundCapability) Status {
	out := Status{State: state.Clone(), Health: "stopped", LocalSOCKSTCP: true, LocalSOCKSUDP: "supported", OutboundAdapters: capabilities, LocalStats: []Observation{}, Outbounds: []OutboundHealth{}, Nodes: []Observation{}, Sessions: []SessionView{}}
	out.Network = m.NetworkStatus()
	out.Accounts = []Observation{}
	for _, kind := range []string{"socks5", "http", "mixed"} {
		out.ProxyInterfaces = append(out.ProxyInterfaces, ports.OutboundCapability{Protocol: kind, Engine: "native", Role: "client_inbound", TCP: true, UDP: kind != "http", IPv4: true, IPv6: true, Domain: true, Qualification: "experimental"})
	}
	out.Underlay = m.underlay.Status()
	out.Host = m.HostStatus()
	out.HostCapabilities = hostnetwork.PlatformCapabilities()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed && m.current.Load() != nil && state.Enabled {
		out.Health = "healthy"
		for _, i := range state.LocalInbounds {
			l := m.listeners[i.ID]
			if l == nil || !l.ready.Load() {
				out.Health = "degraded"
			} else if l.tun != nil && !l.tun.running() {
				out.Health = "degraded"
				out.LastError = "tun_runtime_failed"
			}
		}
	}
	if out.Underlay.Health == "degraded" {
		out.Health = "degraded"
		out.LastError = out.Underlay.LastError
	}
	if out.Host.Recovery == "degraded" {
		out.Health = "degraded"
		out.LastError = out.Host.LastError
	}
	for _, i := range state.LocalInbounds {
		v := Observation{ID: i.ID}
		if c := m.inStats[i.ID]; c != nil {
			v.Stats = c.stats()
		}
		out.LocalStats = append(out.LocalStats, v)
	}
	for _, o := range state.Outbounds {
		v := OutboundHealth{ID: o.ID, Configured: true}
		if c := m.outStats[o.ID]; c != nil {
			v.Stats = c.stats()
			v.Active = v.Stats.Active > 0 || v.Stats.UDPActive > 0
		}
		if current := m.current.Load(); current != nil {
			if lease, ok := current.outbounds[o.ID].(*dialerLease); ok {
				if h := lease.health.Load(); h != nil {
					v.Available = h.available
					v.LastError = h.lastError
				}
			}
		}
		if out.Underlay.Health == "degraded" {
			v.Available = false
			v.LastError = out.Underlay.LastError
		}
		out.Outbounds = append(out.Outbounds, v)
	}
	for _, n := range state.Nodes {
		v := Observation{ID: n.ID}
		if c := m.nodeStats[n.ID]; c != nil {
			v.Stats = c.stats()
		}
		out.Nodes = append(out.Nodes, v)
	}
	for _, s := range m.sessions {
		out.Sessions = append(out.Sessions, SessionView{AccountID: s.account, ID: s.id, InboundID: s.inbound, OutboundID: s.outbound, NodeID: s.node, Kind: s.kind, Stats: s.stats.stats()})
	}
	for id, c := range m.accountStats {
		out.Accounts = append(out.Accounts, Observation{ID: id, Stats: c.stats()})
	}
	sort.Slice(out.Accounts, func(i, j int) bool { return out.Accounts[i].ID < out.Accounts[j].ID })
	sort.Slice(out.Sessions, func(i, j int) bool { return out.Sessions[i].ID < out.Sessions[j].ID })
	return out
}
