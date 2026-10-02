package clientruntime

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"sort"
)

type Observation struct {
	ID    identity.ID `json:"id"`
	Stats ports.Stats `json:"stats"`
}
type OutboundHealth struct {
	ID         identity.ID `json:"id"`
	Configured bool        `json:"configured"`
	Available  bool        `json:"available"`
	Active     bool        `json:"active"`
	LastError  string      `json:"last_error,omitempty"`
	Stats      ports.Stats `json:"stats"`
}
type SessionView struct {
	ID         identity.ID `json:"id"`
	InboundID  identity.ID `json:"local_inbound_id"`
	OutboundID identity.ID `json:"outbound_id"`
	NodeID     identity.ID `json:"node_id,omitempty"`
	Stats      ports.Stats `json:"stats"`
}
type Status struct {
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
	out := Status{State: state.Clone(), Health: "stopped", LocalSOCKSTCP: true, LocalSOCKSUDP: "deferred", OutboundAdapters: capabilities, LocalStats: []Observation{}, Outbounds: []OutboundHealth{}, Nodes: []Observation{}, Sessions: []SessionView{}}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed && m.current.Load() != nil && state.Enabled {
		out.Health = "healthy"
		for _, i := range state.LocalInbounds {
			l := m.listeners[i.ID]
			if l == nil || !l.ready.Load() {
				out.Health = "degraded"
			}
		}
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
			v.Active = v.Stats.Active > 0
			if h := c.health.Load(); h != nil {
				v.Available = h.available
				v.LastError = h.lastError
			}
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
		out.Sessions = append(out.Sessions, SessionView{ID: s.id, InboundID: s.inbound, OutboundID: s.outbound, NodeID: s.node, Stats: s.stats.stats()})
	}
	sort.Slice(out.Sessions, func(i, j int) bool { return out.Sessions[i].ID < out.Sessions[j].ID })
	return out
}
