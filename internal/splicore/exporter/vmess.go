package exporter

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
)

type VMess struct{ Target ports.Format }

func (e VMess) Format() ports.Format { return e.Target }
func (e VMess) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	key, ok := p.Credentials.(access.UUIDPayload)
	o, err := module.DecodeClientOptions(p.Options.Data)
	kind := "none"
	if p.TLS.Enabled {
		kind = "tls"
	}
	if p.Validate() != nil || p.Protocol != module.Key() || !ok || key.Validate() != nil || err != nil || o.UDP != p.UDPPayload || p.Transport.Kind != "tcp" || p.Transport.Path != "" || p.Transport.Host != "" || p.TLS.Validate(kind) != nil || t.Format != e.Target {
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
		u, err := module.EncodeURI(module.URI{Endpoint: p.Endpoint, UUID: key.UUID, Security: o.Security, TLS: p.TLS, Name: name})
		return []byte(u), err
	}
	switch e.Target {
	case ports.SingBox:
		if t.ClientVersion != "1.14.2" {
			return nil, unsupported()
		}
		n := map[string]any{"type": "vmess", "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port, "uuid": key.UUID.Reveal(), "alter_id": 0, "security": o.Security}
		if !o.UDP {
			n["network"] = "tcp"
		}
		if p.TLS.Enabled {
			tls := map[string]any{"enabled": true, "server_name": p.TLS.ServerName, "insecure": false, "alpn": p.TLS.ALPN}
			if p.TLS.Trust == "explicit_ca" {
				tls["certificate"] = []string{p.TLS.CACertificate}
			}
			n["tls"] = tls
		}
		return json.Marshal(n)
	case ports.Mihomo:
		if t.ClientVersion != "1.19.32" || p.TLS.Enabled && p.TLS.Trust != "system" {
			return nil, unsupported()
		}
		n := map[string]any{"type": "vmess", "name": name, "server": p.Endpoint.Host, "port": p.Endpoint.Port, "uuid": key.UUID.Reveal(), "alterId": 0, "cipher": o.Security, "network": "tcp", "tls": p.TLS.Enabled, "udp": o.UDP}
		if p.TLS.Enabled {
			n["servername"], n["alpn"], n["skip-cert-verify"] = p.TLS.ServerName, p.TLS.ALPN, false
		}
		return json.Marshal(map[string]any{"proxies": []any{n}})
	default:
		return nil, unsupported()
	}
}
func (e VMess) Describe(clientprofile.Profile) (ports.ExportDescription, error) {
	shape := "sing-box-outbound"
	if e.Target == ports.URI {
		shape = "vmess-base64-json"
	}
	if e.Target == ports.Mihomo {
		shape = "mihomo-config-fragment"
	}
	return ports.ExportDescription{Compatibility: "modern VMess AEAD/alterId=0; raw TCP/shared TLS; standard bound UDP; no legacy/mux/extensions", ContentShape: shape}, nil
}
