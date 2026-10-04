package ports

import (
	"slices"
)

// EngineStatus reports the compiled Splicore engine.
type EngineStatus struct {
	Engine    string `json:"engine"`
	Available bool   `json:"available"`
}

// EffectiveCapabilities only advertises features implemented by both owners.
func EffectiveCapabilities(p, e Capabilities) Capabilities {
	result := p
	result.Clients = slices.Clone(p.Clients)
	result.Transport.TCP = p.Transport.TCP && e.Transport.TCP
	result.Transport.UDPTransport = p.Transport.UDPTransport && e.Transport.UDPTransport
	result.Transport.UDPPayload = p.Transport.UDPPayload && e.Transport.UDPPayload
	result.Transport.IPv4 = p.Transport.IPv4 && e.Transport.IPv4
	result.Transport.IPv6 = p.Transport.IPv6 && e.Transport.IPv6
	result.Transport.DomainEndpoint = p.Transport.DomainEndpoint && e.Transport.DomainEndpoint
	result.Transport.Kinds = intersect(p.Transport.Kinds, e.Transport.Kinds)
	result.Security.TLS = p.Security.TLS && e.Security.TLS
	result.Security.Reality = p.Security.Reality && e.Security.Reality
	result.Security.Vision = p.Security.Vision && e.Security.Vision
	result.Security.Flows = intersect(p.Security.Flows, e.Security.Flows)
	result.Identity.MultiUserNative = p.Identity.MultiUserNative && e.Identity.MultiUserNative
	result.Identity.PerUserStats = p.Identity.PerUserStats && e.Identity.PerUserStats
	result.Identity.NativeStats = support(p.Identity.NativeStats, e.Identity.NativeStats)
	result.Identity.AttributedPayload = support(p.Identity.AttributedPayload, e.Identity.AttributedPayload)
	result.Policy.Quota = support(p.Policy.Quota, e.Policy.Quota)
	result.Policy.SpeedLimit = support(p.Policy.SpeedLimit, e.Policy.SpeedLimit)
	result.Policy.MaxSessions = support(p.Policy.MaxSessions, e.Policy.MaxSessions)
	result.Mutation.HotReload = p.Mutation.HotReload && e.Mutation.HotReload
	result.Mutation.Users = mutation(p.Mutation.Users, e.Mutation.Users)
	result.Mutation.Listener = mutation(p.Mutation.Listener, e.Mutation.Listener)
	return result
}
func intersect(a, b []string) []string {
	result := []string{}
	for _, x := range a {
		for _, y := range b {
			if x == y {
				result = append(result, x)
				break
			}
		}
	}
	return result
}
func support(a, b Support) Support {
	valid := func(s Support) bool { return s == Native || s == AdapterPending || s == Unsupported }
	if !valid(a) || !valid(b) {
		return Unsupported
	}
	if a == Unsupported || b == Unsupported || a == "" || b == "" {
		return Unsupported
	}
	if a == AdapterPending || b == AdapterPending {
		return AdapterPending
	}
	if a == Native && b == Native {
		return Native
	}
	return Unsupported
}
func mutation(a, b Mutation) Mutation {
	valid := func(m Mutation) bool { return m == Hot || m == Restart || m == MutationUnavailable }
	if !valid(a) || !valid(b) {
		return MutationUnavailable
	}
	if a == MutationUnavailable || b == MutationUnavailable || a == "" || b == "" {
		return MutationUnavailable
	}
	if a == Restart || b == Restart {
		return Restart
	}
	if a == Hot && b == Hot {
		return Hot
	}
	return MutationUnavailable
}
