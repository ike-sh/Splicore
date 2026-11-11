package testfixture

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

// Endpoint parses fixed localhost fixture addresses, including wildcard port 0.
func Endpoint(value string) access.Endpoint {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		panic(err)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		panic(err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	return access.Endpoint{Host: host, Port: uint16(n)}
}
