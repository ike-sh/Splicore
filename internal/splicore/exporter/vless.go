package exporter

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
)

type VLESS struct{ Target ports.Format }

func (e VLESS) Format() ports.Format { return e.Target }
func vlessProfile(p clientprofile.Profile) (access.UUIDPayload, module.ClientOptions, error) {
	credential, ok := p.Credentials.(access.UUIDPayload)
	o, err := module.DecodeClientOptions(p.Options.Data)
	if !ok || p.Validate() != nil || module.ValidateUUID(credential.UUID) != nil || err != nil || p.Protocol != module.Key(o.Security) || p.UDPPayload != (o.Flow != module.Vision) || p.Transport.ValidatePair("vless", string(o.Security)) != nil || len(p.TLS.ALPN) != 0 && p.Transport.Type() != "xhttp" && p.Transport.Type() != "mkcp" {
		return credential, o, unsupported()
	}
	switch o.Security {
	case module.Plain:
		if p.TLS.Enabled || p.TLS.Trust != "" || p.TLS.ServerName != "" || p.TLS.CACertificate != "" || p.TLS.RealityPublicKey != "" || p.TLS.RealityShortID != "" {
			return credential, o, unsupported()
		}
	case module.TLS:
		if !p.TLS.Enabled || p.TLS.Trust != "explicit_ca" || p.TLS.RealityPublicKey != "" || p.TLS.RealityShortID != "" {
			return credential, o, unsupported()
		}
		if _, err := tlsconfig.CAPool(p.TLS.CACertificate); err != nil {
			return credential, o, unsupported()
		}
	case module.Reality:
		if !p.TLS.Enabled || p.TLS.Trust != "reality" || p.TLS.CACertificate != "" || module.ValidatePublicKey(module.PublicKey(p.TLS.RealityPublicKey)) != nil {
			return credential, o, unsupported()
		}
		if _, err := module.ParseShortID(module.ShortID(p.TLS.RealityShortID)); err != nil {
			return credential, o, unsupported()
		}
	}
	if p.Transport.FinalMask != nil || o.Flow == module.Vision && p.Transport.Type() != "tcp" {
		return credential, o, unsupported()
	}
	if o.Security != module.Plain {
		kind, err := access.ParseHost(p.TLS.ServerName)
		if err != nil || kind != access.DNS {
			return credential, o, unsupported()
		}
	}
	return credential, o, nil
}
func (e VLESS) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	credential, o, err := vlessProfile(p)
	if err != nil || t.Format != e.Target {
		return nil, unsupported()
	}
	if o.Flow == module.Vision && e.Target != ports.URI {
		return nil, unsupported()
	}
	name := "splicore-" + string(p.ID)
	switch e.Target {
	case ports.Xray:
		if p.Transport.Type() == "xhttp" || p.Transport.Type() == "mkcp" {
			if t.ClientVersion != "26.10.10" || o.Flow != module.NoFlow {
				return nil, unsupported()
			}
		} else if t.ClientVersion != "26.3.27" || o.Security != module.Plain {
			return nil, unsupported()
		}
		stream := map[string]any{"network": "raw", "security": "none"}
		if p.Transport.Type() == "xhttp" || p.Transport.Type() == "mkcp" {
			stream = xraySecurity(string(o.Security), p.TLS)
		}
		node := map[string]any{"tag": name, "protocol": "vless", "settings": map[string]any{"vnext": []any{
			map[string]any{"address": p.Endpoint.Host, "port": p.Endpoint.Port, "users": []any{map[string]any{"id": credential.UUID.Reveal(), "encryption": "none"}}}}}, "streamSettings": stream}
		if err := streamProjection(p, e.Target, node); err != nil {
			return nil, err
		}
		return json.Marshal(node)
	case ports.Mihomo:
		if t.ClientVersion != "1.19.30" {
			return nil, unsupported()
		}
		node := map[string]any{"name": name, "type": "vless", "server": p.Endpoint.Host, "port": p.Endpoint.Port, "uuid": credential.UUID.Reveal(), "network": "tcp", "udp": true, "packet-encoding": "xudp", "tls": p.TLS.Enabled}
		if p.TLS.Enabled {
			node["servername"] = p.TLS.ServerName
			node["skip-cert-verify"] = false
		}
		if o.Security == module.TLS {
			pin, _ := tlsconfig.CAFingerprint(p.TLS.CACertificate)
			node["fingerprint"] = pin
		}
		if o.Security == module.Reality {
			node["client-fingerprint"] = "chrome"
			node["reality-opts"] = map[string]any{"public-key": p.TLS.RealityPublicKey, "short-id": p.TLS.RealityShortID}
		}
		if err := streamProjection(p, e.Target, node); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"proxies": []any{node}})
	case ports.SingBox:
		if t.ClientVersion != "1.14.1" {
			return nil, unsupported()
		}
		node := map[string]any{"type": "vless", "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port, "uuid": credential.UUID.Reveal(), "packet_encoding": "xudp"}
		if p.TLS.Enabled {
			tls := map[string]any{"enabled": true, "server_name": p.TLS.ServerName, "insecure": false}
			if o.Security == module.TLS {
				tls["certificate"] = []string{p.TLS.CACertificate}
			}
			if o.Security == module.Reality {
				tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
				tls["reality"] = map[string]any{"enabled": true, "public_key": p.TLS.RealityPublicKey, "short_id": p.TLS.RealityShortID}
			}
			node["tls"] = tls
		}
		if err := streamProjection(p, e.Target, node); err != nil {
			return nil, err
		}
		return json.Marshal(node)
	case ports.URI:
		if t.ClientVersion != "" || o.Security == module.TLS {
			return nil, unsupported()
		}
		return renderVLESSURI(p, credential, o)
	default:
		return nil, unsupported()
	}
}
func (e VLESS) Describe(p clientprofile.Profile) (ports.ExportDescription, error) {
	if _, o, err := vlessProfile(p); err != nil || o.Flow == module.Vision && e.Target != ports.URI {
		return ports.ExportDescription{}, unsupported()
	}
	shape := "sing-box-outbound"
	switch e.Target {
	case ports.Xray:
		if p.Transport.Type() == "xhttp" {
			return ports.ExportDescription{Compatibility: "VLESS over XHTTP; Xray 26.10.10; explicit transport/security settings", ContentShape: "xray-outbound"}, nil
		}
		o, err := module.DecodeClientOptions(p.Options.Data)
		if err != nil || o.Security != module.Plain {
			return ports.ExportDescription{}, unsupported()
		}
		return ports.ExportDescription{Compatibility: "VLESS wire 0; plain TCP/XUDP; external client format 26.3.27", ContentShape: "xray-outbound"}, nil
	case ports.Mihomo:
		shape = "mihomo-config-fragment"
	case ports.URI:
		shape = "vless-uri"
	case ports.Surge:
		return ports.ExportDescription{}, unsupported()
	}
	return ports.ExportDescription{ServerVersion: 0, ClientWireVersion: 0, Compatibility: "VLESS wire 0; TCP/XUDP; explicit flow and security", ContentShape: shape}, nil
}
