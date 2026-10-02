package ports

import "testing"

func TestEffectiveCapabilitiesRestrictAndSnapshot(t *testing.T) {
	p := Capabilities{Transport: TransportCapabilities{TCP: true, UDPPayload: true, Kinds: []string{"tcp", "quic"}}, Identity: IdentityCapabilities{PerUserStats: true, NativeStats: Native, AttributedPayload: Native}, Security: SecurityCapabilities{TLS: true, Reality: true, Vision: true, Flows: []string{"none", "xtls-rprx-vision"}}, Mutation: MutationCapabilities{Users: Hot, HotReload: true}, Clients: []ClientCompatibility{{Client: "test"}}}
	e := Capabilities{Transport: TransportCapabilities{TCP: true, Kinds: []string{"tcp"}}, Security: SecurityCapabilities{Reality: true, Flows: []string{"none"}}, Identity: IdentityCapabilities{NativeStats: Unsupported, AttributedPayload: Unsupported}, Mutation: MutationCapabilities{Users: Restart}}
	r := EffectiveCapabilities(p, e)
	if !r.Transport.TCP || r.Transport.UDPPayload || r.Identity.PerUserStats || r.Identity.NativeStats != Unsupported || r.Identity.AttributedPayload != Unsupported || r.Security.TLS || r.Security.Vision || len(r.Security.Flows) != 1 || r.Mutation.Users != Restart || r.Mutation.HotReload {
		t.Fatal("capability overclaim")
	}
	r.Clients[0].Client = "changed"
	r.Security.Flows[0] = "changed"
	r.Transport.Kinds[0] = "changed"
	if p.Clients[0].Client != "test" || p.Security.Flows[0] != "none" || p.Transport.Kinds[0] != "tcp" {
		t.Fatal("snapshot aliased input")
	}
	if support("unknown", Native) != Unsupported || mutation("unknown", Hot) != MutationUnavailable {
		t.Fatal("unknown capability overclaim")
	}
}

func TestEffectiveCapabilitiesUnknownEnumsFailClosed(t *testing.T) {
	for _, value := range []Support{Native, AdapterPending, Unsupported, ""} {
		if support("unknown", value) != Unsupported || support(value, "unknown") != Unsupported {
			t.Fatalf("unknown support with %q", value)
		}
	}
	for _, value := range []Mutation{Hot, Restart, MutationUnavailable, ""} {
		if mutation("unknown", value) != MutationUnavailable || mutation(value, "unknown") != MutationUnavailable {
			t.Fatalf("unknown mutation with %q", value)
		}
	}
}
