// Package clientconfig validates owned node/credential relationships and reports
// the existing managed outbound capability. Wire configuration stays per protocol.
package clientconfig

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func Ownership(n client.RemoteNode, c access.Credential) error {
	if n.Validate() != nil || c.OwnerNodeID == nil || *c.OwnerNodeID != n.ID || c.ID != n.CredentialID {
		return identity.Err(identity.Invalid, "node credential ownership mismatch")
	}
	return nil
}

func Capability(protocol string, tls, quic, reality bool) ports.OutboundCapability {
	return ports.OutboundCapability{Protocol: protocol, Engine: "native", Role: "client_outbound", TCP: true, UDP: true, IPv4: true, IPv6: true, Domain: true, TLS: tls, QUIC: quic, Reality: reality, Flows: []string{"none"}, UDPDomainResolution: "remote", Qualification: "experimental"}
}
