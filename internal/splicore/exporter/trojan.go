package exporter

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
)

type Trojan struct{ Target ports.Format }

func (e Trojan) Format() ports.Format { return e.Target }
func (e Trojan) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	key, ok := p.Credentials.(access.PasswordPayload)
	o, err := module.DecodeClientOptions(p.Options.Data)
	if p.Validate() != nil || p.Protocol != module.Key() || !ok || credential.ValidatePassword(key.Password) != nil || err != nil || p.UDPPayload != o.UDP || p.Transport.Kind != "tcp" || p.Transport.Path != "" || p.Transport.Host != "" || p.TLS.Validate("tls") != nil || t.Format != e.Target {
		return nil, unsupported()
	}
	name := p.Metadata["display_name"]
	if name == "" {
		name = "splicore-" + string(p.ID)
	}
	if e.Target == ports.URI {
		if !o.UDP || t.ClientVersion != "" {
			return nil, unsupported()
		}
		u, err := module.EncodeURI(module.URI{Endpoint: p.Endpoint, Password: key.Password, TLS: p.TLS, Name: name})
		return []byte(u), err
	}
	password := key.Password.Reveal()
	switch e.Target {
	case ports.SingBox:
		if t.ClientVersion != "1.14.1" {
			return nil, unsupported()
		}
		tls := map[string]any{"enabled": true, "server_name": p.TLS.ServerName, "insecure": false, "alpn": p.TLS.ALPN}
		if p.TLS.Trust == "explicit_ca" {
			tls["certificate"] = []string{p.TLS.CACertificate}
		}
		node := map[string]any{"type": "trojan", "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port, "password": password, "tls": tls}
		if !o.UDP {
			node["network"] = "tcp"
		}
		return json.Marshal(node)
	case ports.Mihomo:
		if t.ClientVersion != "1.19.30" {
			return nil, unsupported()
		}
		node := map[string]any{"type": "trojan", "name": name, "server": p.Endpoint.Host, "port": p.Endpoint.Port, "password": password, "sni": p.TLS.ServerName, "skip-cert-verify": false, "udp": o.UDP, "alpn": p.TLS.ALPN}
		if p.TLS.Trust == "explicit_ca" {
			pin, err := tlsconfig.CAFingerprint(p.TLS.CACertificate)
			if err != nil {
				return nil, unsupported()
			}
			node["fingerprint"] = pin
		}
		return json.Marshal(map[string]any{"proxies": []any{node}})
	default:
		return nil, unsupported()
	}
}
func (e Trojan) Describe(clientprofile.Profile) (ports.ExportDescription, error) {
	shape := "sing-box-outbound"
	if e.Target == ports.Mihomo {
		shape = "mihomo-config-fragment"
	}
	if e.Target == ports.URI {
		shape = "trojan-uri"
	}
	return ports.ExportDescription{Compatibility: "standard Trojan TLS/TCP/UDP; verified TLS; no mux; Mihomo datagrams <=8192 bytes", ContentShape: shape}, nil
}
