//go:build with_gvisor

package nativetun

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// The official stack parses and reassembles packets before this callback. Its
// ICMP echo path honors the default handler's consumed result. Local interface
// ICMP retains the built-in reply; forwarded ICMP uses public rejection helpers.
// No custom packet parser, ICMP wire implementation or filter timer is needed.
func (b *gvisorBackend) icmpHandler(protocol tcpip.NetworkProtocolNumber) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	return func(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
		for _, address := range b.runtime.options.Addresses {
			if id.LocalAddress == tcpip.AddrFromSlice(address.AsSlice()) {
				return false
			}
		}
		network := b.stack.NetworkProtocolInstance(protocol)
		if protocol == header.IPv4ProtocolNumber {
			_ = network.(stack.RejectIPv4WithHandler).SendRejectionError(packet, stack.RejectIPv4WithICMPHostUnreachable, stack.Input)
		} else {
			_ = network.(stack.RejectIPv6WithHandler).SendRejectionError(packet, stack.RejectIPv6WithICMPAddrUnreachable, stack.Input)
		}
		return true
	}
}
