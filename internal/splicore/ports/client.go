package ports

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"net"
)

type Roles struct {
	Inbound  bool `json:"inbound"`
	Outbound bool `json:"outbound"`
}
type OutboundCapability struct {
	Protocol            string   `json:"protocol"`
	Engine              string   `json:"engine"`
	TCP                 bool     `json:"tcp"`
	UDP                 bool     `json:"udp"`
	Role                string   `json:"role"`
	IPv4                bool     `json:"ipv4"`
	IPv6                bool     `json:"ipv6"`
	Domain              bool     `json:"domain"`
	TLS                 bool     `json:"tls"`
	QUIC                bool     `json:"quic"`
	Reality             bool     `json:"reality"`
	Flows               []string `json:"flows"`
	UDPDomainResolution string   `json:"udp_domain_resolution"`
	Qualification       string   `json:"qualification"`
}
type ClientDialer interface {
	DialContext(context.Context, access.Endpoint) (net.Conn, error)
	Close() error
}

// ClientPacketDialer is separate from local SOCKS UDP admission.
type ClientPacketDialer interface {
	ListenPacket(context.Context, access.Endpoint) (net.PacketConn, error)
}
type OutboundFactory interface {
	Capability() OutboundCapability
	Validate(client.RemoteNode, access.Credential) error
	Build(context.Context, client.RemoteNode, access.Credential) (ClientDialer, error)
}
type ClientRepository interface {
	RuntimeRepository
	ClientState(context.Context) (client.ProfileState, error)
}
type ClientWriter interface {
	ReplaceClient(client.ProfileState, []access.Credential) error
}
type ClientPlan struct {
	Revision identity.Revision `json:"revision"`
	Digest   string            `json:"digest"`
	Resource string            `json:"resource"`
	Action   string            `json:"action"`
}
