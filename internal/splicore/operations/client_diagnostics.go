package operations

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/clientruntime"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"strconv"
	"time"
)

type clientSupportSource interface {
	ClientStatus(context.Context) (clientruntime.Status, error)
}
type providerSummary struct {
	Kind              string            `json:"kind"`
	Format            string            `json:"format"`
	Status            string            `json:"status"`
	LastError         string            `json:"last_error"`
	Generation        identity.Revision `json:"generation"`
	Nodes             int               `json:"node_count"`
	Stale             int               `json:"stale_nodes"`
	RefreshAgeSeconds int64             `json:"refresh_age_seconds"`
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
	Kind         string      `json:"kind"`
	AddressClass string      `json:"address_class"`
	Port         uint16      `json:"port"`
	TUN          *tunSummary `json:"tun,omitempty"`
}
type tunSummary struct {
	MTU             uint32 `json:"mtu"`
	AddressFamilies int    `json:"address_families"`
	AutoRoute       bool   `json:"auto_route"`
	DNSMode         string `json:"dns_mode"`
	IncludeCount    int    `json:"include_count"`
	ExcludeCount    int    `json:"exclude_count"`
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
	Providers   []providerSummary `json:"providers"`
	Underlay    underlay.Status   `json:"underlay"`
	HostNetwork struct {
		Recovery    string `json:"recovery"`
		Interfaces  int    `json:"owned_interfaces"`
		Routes      int    `json:"owned_routes"`
		SystemProxy bool   `json:"system_proxy_owned"`
	} `json:"host_network"`
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
	result.Underlay = s.Underlay
	result.HostNetwork.Recovery = enum(s.Host.Recovery, "clean", "degraded", "unconfigured")
	result.HostNetwork.Interfaces = s.Host.OwnedInterfaces
	result.HostNetwork.Routes = s.Host.OwnedRoutes
	result.HostNetwork.SystemProxy = s.Host.SystemProxy
	result.Enabled = s.State.Enabled
	for _, p := range s.State.Management.Providers {
		age := int64(0)
		if !p.LastSuccess.IsZero() {
			age = max(0, int64(time.Since(p.LastSuccess).Seconds()))
		}
		nodes, stale := 0, 0
		for _, n := range s.State.Nodes {
			if n.Provenance.ProviderID == p.ID {
				nodes++
				if n.State == "stale" {
					stale++
				}
			}
		}
		result.Providers = append(result.Providers, providerSummary{Kind: enum(p.Kind, "proxy", "ruleset"), Format: enum(p.Format, "auto", "uri", "base64", "canonical", "mieru", "mihomo", "sing-box", "canonical-rules", "mihomo-domain", "mihomo-ipcidr", "mihomo-classical"), Status: enum(p.Status, "new", "healthy", "degraded"), LastError: enum(p.LastError, "", "fetch_failed", "parse_failed", "validation_failed", "apply_failed", "safety_guard", "revision_changed"), Generation: p.Generation, Nodes: nodes, Stale: stale, RefreshAgeSeconds: age})
	}
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
		result.Outbounds = append(result.Outbounds, clientOutboundSummary{Kind: enum(o.Kind, "direct", "proxy"), Engine: enum(o.Engine, "native"), Configured: h.Configured, Available: h.Available, Active: h.Active, LastError: enum(h.LastError, "", "outbound_connection_failed")})
	}
	for _, n := range s.State.Nodes {
		v := clientNodeSummary{Name: "[REDACTED]", Protocol: enum(n.Protocol.Protocol, "snell", "hysteria2", "tuic", "vless", "mieru", "shadowsocks"), EndpointClass: addressClass(n.Endpoint.Host), Port: n.Endpoint.Port, Engines: []string{}}
		for _, o := range s.State.Outbounds {
			if o.NodeID != nil && *o.NodeID == n.ID {
				v.Engines = append(v.Engines, enum(o.Engine, "native"))
				v.Available = v.Available || health[o.ID].Available
			}
		}
		result.Nodes = append(result.Nodes, v)
	}
	for _, i := range s.State.LocalInbounds {
		v := clientListenerSummary{Kind: enum(i.Kind, "socks5", "http", "mixed", "tun"), AddressClass: addressClass(i.Listen.Host), Port: i.Listen.Port}
		if i.TUN != nil {
			mode := "unchanged"
			if i.TUN.DNSHijack {
				mode = "intercept-tcp-udp-53"
			}
			v.AddressClass = "owned-tun"
			v.TUN = &tunSummary{MTU: i.TUN.MTU, AddressFamilies: len(i.TUN.Addresses), AutoRoute: i.TUN.AutoRoute, DNSMode: mode, IncludeCount: len(i.TUN.Include), ExcludeCount: len(i.TUN.Exclude)}
		}
		result.Listeners = append(result.Listeners, v)
	}
	return result
}

// ClientDoctorChecks are passive observations, never reachability probes.
func ClientDoctorChecks(s *clientruntime.Status) []application.Check {
	if s == nil {
		return []application.Check{{Name: "client_runtime", Status: "info", Detail: "unavailable"}}
	}
	count := func(n int) string { return strconv.Itoa(n) + " configured" }
	runtimeStatus := "info"
	if s.Health == "degraded" || s.State.Enabled && s.Health != "healthy" {
		runtimeStatus = "fail"
	} else if s.Health == "healthy" {
		runtimeStatus = "pass"
	}
	checks := []application.Check{{Name: "client_runtime", Status: runtimeStatus, Detail: enum(s.Health, "healthy", "degraded", "stopped")}, {Name: "remote_nodes", Status: "info", Detail: count(len(s.State.Nodes))}, {Name: "client_outbounds", Status: "info", Detail: count(len(s.State.Outbounds))}, {Name: "local_listeners", Status: "info", Detail: count(len(s.LocalStats))}, {Name: "client_route", Status: "info", Detail: "committed default and selected outbound references"}, {Name: "client_health", Status: "info", Detail: "passive only; remote reachability not probed"}}
	c := s.HostCapabilities
	u := s.Underlay
	underlayHealth := enum(u.Health, "healthy", "degraded")
	underlayStatus := "info"
	if underlayHealth == "degraded" {
		underlayStatus = "fail"
	}
	checks = append(checks, application.Check{Name: "underlay_protection", Status: underlayStatus, Detail: underlayHealth}, application.Check{Name: "underlay_strategy", Status: "info", Detail: enum(u.Strategy, "socket-mark-and-journaled-daemon-uid", "interface-and-endpoint-leases", "activation-unqualified")}, application.Check{Name: "underlay_generations", Status: "info", Detail: strconv.Itoa(len(u.Generations)) + " active"}, application.Check{Name: "underlay_infrastructure", Status: "info", Detail: strconv.Itoa(u.Endpoints) + " infrastructure addresses; arbitrary target history is not retained"}, application.Check{Name: "underlay_unprotected", Status: underlayStatus, Detail: strconv.Itoa(u.Unprotected) + " required runtimes"}, application.Check{Name: "underlay_dependency_loop", Status: "info", Detail: "canonical dependency validation required before runtime preparation"})
	checks = append(checks, application.Check{Name: "tun_capability", Status: "info", Detail: enum(c.TUN, "experimental", "experimental-not-certified", "unsupported", "build-unavailable")}, application.Check{Name: "tun_stack", Status: "info", Detail: enum(c.Stack, "gvisor", "not-included")}, application.Check{Name: "tun_privileges", Status: "info", Detail: enum(c.Privilege, "CAP_NET_ADMIN-required", "elevation-required", "elevated", "unsupported")}, application.Check{Name: "tun_auto_route", Status: "info", Detail: enum(c.AutoRoute, "implemented", "unsupported")}, application.Check{Name: "loop_exclusions", Status: "info", Detail: enum(c.LoopProtection, "dedicated-daemon-uid-main-table", "auto-route-fail-closed", "unsupported")}, application.Check{Name: "host_routes", Status: "info", Detail: strconv.Itoa(s.Host.OwnedRoutes) + " owned"}, application.Check{Name: "system_proxy_owned", Status: "info", Detail: strconv.FormatBool(s.Host.SystemProxy)})
	driver := enum(c.Driver, "linux-tun", "missing-or-inaccessible", "missing", "unavailable", "available-version-unknown", "unsupported")
	if driver == "unknown" {
		driver = "available-version-reported"
	}
	checks = append(checks, application.Check{Name: "tun_driver", Status: "info", Detail: driver})
	status := "info"
	if s.Host.Recovery == "degraded" {
		status = "fail"
	}
	checks = append(checks, application.Check{Name: "host_network_journal", Status: status, Detail: enum(s.Host.Recovery, "clean", "degraded", "unconfigured")})
	intercept := 0
	for _, i := range s.State.LocalInbounds {
		if i.TUN != nil && i.TUN.DNSHijack {
			intercept++
		}
	}
	checks = append(checks, application.Check{Name: "dns_interception", Status: "info", Detail: strconv.Itoa(intercept) + " owned TCP/UDP53 listeners; host DNS unchanged"})
	return checks
}
