package xray

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	clientdomain "github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/engine/clientio"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"net"
	"strconv"
	"strings"
	"time"
)

type OutboundFactory struct{ Engine *Engine }

func (OutboundFactory) Capability() ports.OutboundCapability {
	return ports.OutboundCapability{Protocol: "vless", Engine: "xray", Role: "client_outbound", TCP: true, UDP: true, IPv4: true, IPv6: true, Domain: true, TLS: true, Reality: true, Flows: []string{"none"}, UDPDomainResolution: "remote", Qualification: "experimental"}
}
func (OutboundFactory) Validate(n clientdomain.RemoteNode, c access.Credential) error {
	return v.ValidateClientNode(n, c)
}

type vlessOutboundSettings struct {
	Servers []vlessRemote `json:"vnext"`
}
type vlessRemote struct {
	Address string      `json:"address"`
	Port    uint16      `json:"port"`
	Users   []vlessUser `json:"users"`
}
type vlessUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow"`
}
type clientStreamConfig struct {
	Network  string           `json:"network"`
	Security string           `json:"security"`
	Reality  *clientReality   `json:"realitySettings,omitempty"`
	TLS      *clientTLSConfig `json:"tlsSettings,omitempty"`
}
type clientReality struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
}
type clientTLSConfig struct {
	ServerName        string              `json:"serverName"`
	ALPN              []string            `json:"alpn,omitempty"`
	DisableSystemRoot bool                `json:"disableSystemRoot,omitempty"`
	Certificates      []clientCertificate `json:"certificates,omitempty"`
}
type clientCertificate struct {
	Certificate []string `json:"certificate"`
	Usage       string   `json:"usage"`
}

func renderClient(n clientdomain.RemoteNode, c access.Credential) ([]byte, error) {
	if err := v.ValidateClientNode(n, c); err != nil {
		return nil, err
	}
	stream := &clientStreamConfig{Network: "raw", Security: n.Security.Kind}
	t := n.Security.TLS
	if n.Security.Kind == "reality" {
		stream.Reality = &clientReality{ServerName: t.ServerName, Fingerprint: "chrome", PublicKey: t.RealityPublicKey, ShortID: t.RealityShortID}
	}
	if n.Security.Kind == "tls" {
		stream.TLS = &clientTLSConfig{ServerName: t.ServerName, ALPN: append([]string(nil), t.ALPN...)}
		if t.CACertificate != "" {
			// explicit_ca is an exclusive trust store, including on Windows where
			// a system pool cannot reliably act as a custom-only verifier.
			stream.TLS.DisableSystemRoot = true
			stream.TLS.Certificates = []clientCertificate{{Certificate: strings.Split(t.CACertificate, "\n"), Usage: "verify"}}
		}
	}
	config := configuration{Inbounds: []inboundConfig{{Tag: "managed-client", Listen: "127.0.0.1", Port: 1, Protocol: "socks", Settings: userConfig{Auth: "noauth", UDP: true, IP: "127.0.0.1"}, Stream: streamConfig{Network: "raw", Security: "none"}}}, Outbounds: []outboundConfig{{Protocol: "vless", Tag: "managed", Settings: &vlessOutboundSettings{Servers: []vlessRemote{{Address: n.Endpoint.Host, Port: n.Endpoint.Port, Users: []vlessUser{{ID: c.Payload.(access.UUIDPayload).UUID.Reveal(), Encryption: "none", Flow: ""}}}}}, Stream: stream}}}
	config.Log.Level = "none"
	return json.Marshal(config)
}
func (f OutboundFactory) Build(ctx context.Context, n clientdomain.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	b, err := renderClient(n, c)
	if err != nil {
		return nil, err
	}
	if f.Engine == nil {
		clear(b)
		return nil, unavailable("Xray engine unavailable")
	}
	h := newHandle(f.Engine, access.Endpoint{}, b)
	h.clientRole = true
	f.Engine.mu.Lock()
	if f.Engine.closed {
		f.Engine.mu.Unlock()
		clear(b)
		return nil, unavailable("Xray engine closed")
	}
	f.Engine.handles[h] = true
	f.Engine.mu.Unlock()
	if err = h.Start(ctx); err != nil {
		_ = h.Close(context.Background())
		return nil, err
	}
	h.Activate()
	return &clientDialer{handle: h, owner: clientio.New()}, nil
}

type clientDialer struct {
	handle *Handle
	owner  *clientio.Owner
}

func (d *clientDialer) handshake(ctx context.Context, command byte, target M.Socksaddr) (net.Conn, M.Socksaddr, error) {
	h := d.handle
	h.mu.Lock()
	port := h.privatePort
	closed := h.closed || h.status.ExitCode != nil
	h.mu.Unlock()
	if closed {
		return nil, M.Socksaddr{}, net.ErrClosed
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	c, err = d.owner.Conn(c)
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	deadline := time.Now().Add(5 * time.Second)
	if at, ok := ctx.Deadline(); ok && at.Before(deadline) {
		deadline = at
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	bind, err := socks.ClientHandshake5(c, command, target, "", "")
	stop()
	if err != nil || ctx.Err() != nil {
		_ = c.Close()
		if err == nil {
			err = ctx.Err()
		}
		return nil, M.Socksaddr{}, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, bind.Bind, nil
}
func (d *clientDialer) DialContext(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	joined, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	c, _, err := d.handshake(joined, socks5.CommandConnect, M.ParseSocksaddrHostPort(e.Host, e.Port))
	if err != nil {
		return nil, err
	}
	// The private TCP socket's CloseWrite does not establish an end-to-end
	// half-close contract through every supported VLESS server. Expose the
	// stream contract only, so application EOF closes this owned tunnel instead
	// of retaining a session waiting for a FIN the remote wrapper cannot convey.
	return &clientStream{Conn: c}, nil
}

type clientStream struct{ net.Conn }

func (d *clientDialer) ListenPacket(ctx context.Context, e access.Endpoint) (net.PacketConn, error) {
	joined, done, err := d.owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	control, bind, err := d.handshake(joined, socks5.CommandUDPAssociate, M.ParseSocksaddr("0.0.0.0:0"))
	if err != nil {
		return nil, err
	}
	udp, err := (&net.Dialer{}).DialContext(joined, "udp4", bind.String())
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	pc := socks.NewAssociatePacketConn(udp, M.ParseSocksaddrHostPort(e.Host, e.Port), control)
	return d.owner.Packet(&clientPacket{pc})
}

type clientPacket struct{ *socks.AssociatePacketConn }

// The inherited ReadFrom projection calls UDPAddr(), losing FQDN responses.
// Use its existing packet decoder and preserve the full SOCKS address instead.
func (p *clientPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	buffer := buf.With(b)
	destination, err := p.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	n := copy(b, buffer.Bytes())
	return n, destination, nil
}
func (d *clientDialer) Close() error { d.owner.Close(); return d.handle.Close(context.Background()) }
