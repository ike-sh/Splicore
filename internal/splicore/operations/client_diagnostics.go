package operations

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/clientruntime"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"strconv"
)

type clientSupportSource interface {
	ClientStatus(context.Context) (clientruntime.Status, error)
}
type clientNodeSummary struct {
	Name          string   `json:"name"`
	Protocol      string   `json:"protocol"`
	EndpointClass string   `json:"endpoint_address_class"`
	Port          uint16   `json:"endpoint_port"`
	Engines       []string `json:"engines"`
	Available     bool     `json:"available"`
}
type clientListenerSummary struct {
	Kind         string `json:"kind"`
	AddressClass string `json:"address_class"`
	Port         uint16 `json:"port"`
}
type clientOutboundSummary struct {
	Kind       string `json:"kind"`
	Engine     string `json:"engine"`
	Configured bool   `json:"configured"`
	Available  bool   `json:"available"`
	Active     bool   `json:"active"`
	LastError  string `json:"last_error,omitempty"`
}
type clientSummary struct {
	Health        string                  `json:"health"`
	Enabled       bool                    `json:"enabled"`
	LocalSOCKSTCP bool                    `json:"local_socks_tcp"`
	LocalSOCKSUDP string                  `json:"local_socks_udp"`
	DefaultRoute  string                  `json:"default_route"`
	Nodes         []clientNodeSummary     `json:"nodes"`
	Outbounds     []clientOutboundSummary `json:"outbounds"`
	Listeners     []clientListenerSummary `json:"listeners"`
	Sessions      int                     `json:"sessions_active"`
}

func clientProjection(ctx context.Context, q SupportSource) clientSummary {
	result := clientSummary{Health: "unavailable", LocalSOCKSUDP: "deferred", Nodes: []clientNodeSummary{}, Outbounds: []clientOutboundSummary{}, Listeners: []clientListenerSummary{}}
	source, ok := q.(clientSupportSource)
	if !ok {
		return result
	}
	s, err := source.ClientStatus(ctx)
	if err != nil {
		return result
	}
	result.Health = enum(s.Health, "healthy", "degraded", "stopped")
	result.Enabled = s.State.Enabled
	result.LocalSOCKSTCP = s.LocalSOCKSTCP
	result.LocalSOCKSUDP = enum(s.LocalSOCKSUDP, "deferred", "supported")
	result.Sessions = len(s.Sessions)
	health := map[identity.ID]clientruntime.OutboundHealth{}
	for _, o := range s.Outbounds {
		health[o.ID] = o
	}
	result.DefaultRoute = "proxy"
	if s.State.Route.DefaultOutbound == client.Direct {
		result.DefaultRoute = "direct"
	}
	for _, o := range s.State.Outbounds {
		h := health[o.ID]
		result.Outbounds = append(result.Outbounds, clientOutboundSummary{Kind: enum(o.Kind, "direct", "proxy"), Engine: enum(o.Engine, "native", "xray"), Configured: h.Configured, Available: h.Available, Active: h.Active, LastError: enum(h.LastError, "", "outbound_connection_failed")})
	}
	for _, n := range s.State.Nodes {
		v := clientNodeSummary{Name: "[REDACTED]", Protocol: enum(n.Protocol.Protocol, "snell"), EndpointClass: addressClass(n.Endpoint.Host), Port: n.Endpoint.Port, Engines: []string{}}
		for _, o := range s.State.Outbounds {
			if o.NodeID != nil && *o.NodeID == n.ID {
				v.Engines = append(v.Engines, enum(o.Engine, "native", "xray"))
				v.Available = v.Available || health[o.ID].Available
			}
		}
		result.Nodes = append(result.Nodes, v)
	}
	for _, i := range s.State.LocalInbounds {
		result.Listeners = append(result.Listeners, clientListenerSummary{Kind: enum(i.Kind, "socks5"), AddressClass: addressClass(i.Listen.Host), Port: i.Listen.Port})
	}
	return result
}

// ClientDoctorChecks are passive observations, never reachability probes.
func ClientDoctorChecks(s *clientruntime.Status) []application.Check {
	if s == nil {
		return []application.Check{{Name: "client_runtime", Status: "info", Detail: "unavailable"}}
	}
	count := func(n int) string { return strconv.Itoa(n) + " configured" }
	return []application.Check{{Name: "client_runtime", Status: "info", Detail: enum(s.Health, "healthy", "degraded", "stopped")}, {Name: "remote_nodes", Status: "info", Detail: count(len(s.State.Nodes))}, {Name: "client_outbounds", Status: "info", Detail: count(len(s.State.Outbounds))}, {Name: "local_listeners", Status: "info", Detail: count(len(s.LocalStats))}, {Name: "client_route", Status: "info", Detail: "committed default and selected outbound references"}, {Name: "client_health", Status: "info", Detail: "passive only; remote reachability not probed"}}
}
