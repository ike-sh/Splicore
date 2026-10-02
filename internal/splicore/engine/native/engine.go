package native

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"slices"
)

// Compiler is protocol-specific; registry dispatch and lifecycle remain shared.
type Compiler interface {
	ProtocolID() string
	Supports(ports.RuntimeIntent) error
	Compile(context.Context, ports.RuntimeIntent) (ports.PreparedRuntime, error)
}
type Engine struct{ compilers map[string]Compiler }

func NewEngine(entries ...Compiler) (Engine, error) {
	e := Engine{compilers: map[string]Compiler{}}
	for _, c := range entries {
		if c == nil || e.compilers[c.ProtocolID()] != nil {
			return e, identity.Err(identity.Invalid, "duplicate native compiler")
		}
		e.compilers[c.ProtocolID()] = c
	}
	return e, nil
}
func (e Engine) Metadata() ports.EngineMetadata {
	protocols := []string{}
	if e.compilers == nil {
		protocols = append(protocols, "snell")
	}
	for id := range e.compilers {
		protocols = append(protocols, id)
	}
	slices.Sort(protocols)
	return ports.EngineMetadata{ID: "native", Availability: ports.Compiled, RuntimeImplemented: true, ABI: 1, Protocols: protocols}
}
func (Engine) Capabilities() ports.Capabilities {
	return ports.Capabilities{Transport: ports.TransportCapabilities{Kinds: []string{"tcp", "udp", "quic"}, TCP: true, UDPTransport: true, UDPPayload: true, IPv4: true, IPv6: true, DomainEndpoint: true}, Identity: ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native}, Security: ports.SecurityCapabilities{TLS: true, Reality: true, Flows: []string{"none"}}, Policy: ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported}, Mutation: ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable}}
}
func (e Engine) compiler(in ports.RuntimeIntent) (Compiler, error) {
	if in.Inbound.Engine != "native" {
		return nil, identity.Err(identity.Invalid, "engine binding mismatch")
	}
	if e.compilers == nil {
		e.compilers = map[string]Compiler{"snell": SnellCompiler{}}
	}
	c := e.compilers[in.Inbound.Protocol.Protocol]
	if c == nil {
		return nil, identity.Err(identity.NotImplemented, "native compiler unavailable")
	}
	return c, nil
}
func (e Engine) Supports(in ports.RuntimeIntent) error {
	c, err := e.compiler(in)
	if err != nil {
		return err
	}
	return c.Supports(in)
}
func (e Engine) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	c, err := e.compiler(in)
	if err != nil {
		return nil, err
	}
	return c.Compile(ctx, in)
}
