// Package netaddr converts owned semantic endpoints at stdlib socket boundaries.
// Domain addresses remain semantic; resolution belongs to the protected dialer.
package netaddr

import (
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func From(a net.Addr) (access.Endpoint, error) {
	if a == nil {
		return access.Endpoint{}, errors.New("missing network address")
	}
	if v, ok := a.(endpointAddr); ok {
		return v.endpoint, nil
	}
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return access.Endpoint{}, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return access.Endpoint{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	return access.Endpoint{Host: host, Port: uint16(n)}, nil
}

func UDP(e access.Endpoint) net.Addr {
	if ip, err := netip.ParseAddr(e.Host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), e.Port))
	}
	return endpointAddr{endpoint: e, network: "udp"}
}
func TCP(e access.Endpoint) net.Addr {
	if ip, err := netip.ParseAddr(e.Host); err == nil {
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), e.Port))
	}
	return endpointAddr{endpoint: e, network: "tcp"}
}

type endpointAddr struct {
	endpoint access.Endpoint
	network  string
}

func (a endpointAddr) Network() string { return a.network }
func (a endpointAddr) String() string {
	return net.JoinHostPort(a.endpoint.Host, strconv.Itoa(int(a.endpoint.Port)))
}
