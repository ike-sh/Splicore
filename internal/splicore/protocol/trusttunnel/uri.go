package trusttunnel

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/deeplink"
)

// ImportLink rejects optional features with no corresponding Core policy. It
// never strips subscription credentials, DNS policy or anti-DPI settings into
// an ordinary runnable profile.
func ImportLink(raw string) (client.RemoteNode, string, string, error) {
	l, e := deeplink.Parse(raw)
	if e != nil {
		return client.RemoteNode{}, "", "", invalid()
	}
	if l.SubscriptionURL != "" || l.AntiDPI || l.ClientRandomPrefix != "" || l.ClientRandomAuthKey != "" || len(l.DNSUpstreams) > 0 {
		return client.RemoteNode{}, "", "", identity.Err(identity.UnsupportedExport, "TrustTunnel subscription, DNS policy or TLS extension requires unsupported profile policy")
	}
	host, port, _ := net.SplitHostPort(l.Addresses[0])
	number, _ := strconv.ParseUint(port, 10, 16)
	name := l.Name
	if name == "" {
		name = "TrustTunnel"
	}
	if !identity.Label(name, 128) {
		return client.RemoteNode{}, "", "", invalid()
	}
	tls := access.ClientTLS{Enabled: true, ServerName: l.Hostname, Trust: "system"}
	if len(l.Certificate) > 0 {
		certs, e := x509.ParseCertificates(l.Certificate)
		if e != nil {
			return client.RemoteNode{}, "", "", invalid()
		}
		tls.Trust = "explicit_ca"
		for _, cert := range certs {
			tls.CACertificate += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}
	}
	o := ClientOptions{Mode: l.Protocol, Addresses: l.Addresses, CustomSNI: l.CustomSNI, Insecure: l.SkipVerification, DisableIPv6: !l.HasIPv6}
	options, _ := json.Marshal(o)
	node := client.RemoteNode{Name: name, Protocol: Key(), Endpoint: access.Endpoint{Host: host, Port: uint16(number)}, Transport: client.Transport{Kind: Carrier(o.Mode)}, Security: client.Security{Kind: "tls", TLS: tls}, Options: client.Options{Schema: 1, Data: options}, Metadata: identity.Metadata{}}
	return node, l.Username, l.Password, nil
}
func ExportLink(p clientprofile.Profile) (string, error) {
	o, e := DecodeClient(p.Options.Data)
	pair, ok := p.Credentials.(access.UsernamePasswordPayload)
	if p.Validate() != nil || p.Protocol != Key() || p.TLS.Validate("tls") != nil || e != nil || !ok || o.Mode == "auto" || p.Transport.Kind != Carrier(o.Mode) || p.Transport.Path != "" || p.Transport.Host != "" || len(p.Transport.Headers) != 0 || p.Transport.FinalMask != nil || p.Transport.XHTTP != nil || p.Transport.Hysteria != nil || p.Transport.MKCP != nil || p.Transport.ServiceName != "" || !p.UDPPayload || o.UserAgent != "" || o.MaxStreams != 256 || o.MaxFlows != 256 || o.ConnectTimeout != "" || o.HealthTimeout != "" || o.FallbackDelay != "" || o.IdleTimeout != "" || o.UDPIdleTimeout != "" || len(p.TLS.ALPN) > 0 {
		return "", identity.Err(identity.UnsupportedExport, "TrustTunnel profile cannot be losslessly represented by deep link")
	}
	addresses := o.Addresses
	if len(addresses) == 0 {
		addresses = []string{Address(p.Endpoint)}
	}
	l := deeplink.Link{Hostname: p.TLS.ServerName, Addresses: addresses, CustomSNI: o.CustomSNI, HasIPv6: !o.DisableIPv6, Username: pair.Username.Reveal(), Password: pair.Password.Reveal(), SkipVerification: o.Insecure, Protocol: o.Mode, Name: p.Metadata["display_name"]}
	if l.Name == "" {
		l.Name = fmt.Sprint("splicore-", p.ID)
	}
	if p.TLS.CACertificate != "" {
		b := []byte(p.TLS.CACertificate)
		for len(b) > 0 {
			block, rest := pem.Decode(b)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return "", invalid()
			}
			l.Certificate = append(l.Certificate, block.Bytes...)
			b = rest
		}
	}
	return deeplink.Encode(l)
}
