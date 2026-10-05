//go:build with_gvisor

package nativetun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestICMPLocalInterfaceAndForwardReject(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(map[bool]string{true: "local", false: "forwarded"}[local], func(t *testing.T) {
			device := newTestDevice()
			output := make(chan []byte, 2)
			device.write = func(p []byte) (int, error) { output <- append([]byte(nil), p...); return len(p), nil }
			r, err := New(context.Background(), device, Options{MTU: 1500, Addresses: []netip.Addr{netip.MustParseAddr("198.18.0.1")}, Dispatcher: testDispatcher{}})
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Start(); err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
			destination := [4]byte{198, 19, 0, 1}
			if local {
				destination = [4]byte{198, 18, 0, 1}
			}
			ip := header.IPv4(packet)
			ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.ICMPv4ProtocolNumber), SrcAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), DstAddr: tcpip.AddrFrom4(destination)})
			ip.SetChecksum(^ip.CalculateChecksum())
			icmp := header.ICMPv4(packet[header.IPv4MinimumSize:])
			icmp.SetType(header.ICMPv4Echo)
			icmp.SetChecksum(^checksum.Checksum(icmp, 0))
			device.read <- packet
			select {
			case response := <-output:
				ip := header.IPv4(response)
				reply := header.ICMPv4(response[ip.HeaderLength():])
				if local && reply.Type() != header.ICMPv4EchoReply {
					t.Fatal("local ICMP changed", reply.Type())
				}
				if !local && (reply.Type() != header.ICMPv4DstUnreachable || reply.Code() != header.ICMPv4HostUnreachable) {
					t.Fatal("forwarded ICMP unexpectedly accepted", reply.Type(), reply.Code())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("ICMP reply missing")
			}
		})
	}
}

func TestICMPv6LocalInterfaceAndForwardReject(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(map[bool]string{true: "local", false: "forwarded"}[local], func(t *testing.T) {
			device := newTestDevice()
			output := make(chan []byte, 4)
			device.write = func(p []byte) (int, error) { output <- append([]byte(nil), p...); return len(p), nil }
			address := netip.MustParseAddr("fd13::1")
			r, err := New(context.Background(), device, Options{MTU: 1500, Addresses: []netip.Addr{address}, Dispatcher: testDispatcher{}})
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Start(); err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			destination := netip.MustParseAddr("fd13:5678::1")
			if local {
				destination = address
			}
			source := tcpip.AddrFromSlice(netip.MustParseAddr("fd13::2").AsSlice())
			dest := tcpip.AddrFromSlice(destination.AsSlice())
			packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize)
			header.IPv6(packet).Encode(&header.IPv6Fields{PayloadLength: header.ICMPv6MinimumSize, TransportProtocol: header.ICMPv6ProtocolNumber, HopLimit: 64, SrcAddr: source, DstAddr: dest})
			icmp := header.ICMPv6(packet[header.IPv6MinimumSize:])
			icmp.SetType(header.ICMPv6EchoRequest)
			icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: source, Dst: dest}))
			device.read <- packet
			select {
			case response := <-output:
				reply := header.ICMPv6(response[header.IPv6MinimumSize:])
				if local && reply.Type() != header.ICMPv6EchoReply {
					t.Fatal("local ICMPv6 changed", reply.Type())
				}
				if !local && (reply.Type() != header.ICMPv6DstUnreachable || reply.Code() != header.ICMPv6AddressUnreachable) {
					t.Fatal("forwarded ICMPv6 unexpectedly accepted", reply.Type(), reply.Code())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("ICMPv6 reply missing")
			}
		})
	}
}
