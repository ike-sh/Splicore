package ports

import "testing"

func TestCapabilityDimensions(t *testing.T) {
	c := Capabilities{Transport: TransportCapabilities{UDPPayload: true, IPv6: true, DomainEndpoint: true}, Identity: IdentityCapabilities{MultiUserNative: true, AttributedPayload: AdapterPending, NativeStats: Native, StatsUnits: "payload_bytes"}, Policy: PolicyCapabilities{Quota: Unsupported, SpeedLimit: AdapterPending}, Mutation: MutationCapabilities{Users: Restart, Listener: Restart}, Security: SecurityCapabilities{TLS: true, Reality: true}, Clients: []ClientCompatibility{{Format: Mihomo, Client: "dummy-client", Version: "fixture", Evidence: "test-only"}}}
	if c.Transport.UDPTransport || c.Mutation.HotReload || c.Policy.Quota != Unsupported || c.Identity.AttributedPayload == Native {
		t.Fatal("independent capabilities conflated")
	}
}
