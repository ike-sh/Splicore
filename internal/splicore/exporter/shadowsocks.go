package exporter

import (
	"context"
	"encoding/json"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
)

type Shadowsocks struct{ Target ports.Format }

func (e Shadowsocks) Format() ports.Format { return e.Target }
func (e Shadowsocks) Describe(p clientprofile.Profile) (ports.ExportDescription, error) {
	o, err := module.DecodeClient(p.Options.Data)
	if err != nil {
		return ports.ExportDescription{}, unsupported()
	}
	m, _ := module.Lookup(o.Method)
	v := 2017
	if m.Edition == "2022" {
		v = 2022
	}
	shape := "uri"
	if e.Target == ports.SingBox {
		shape = "sing-box-outbound"
	}
	if e.Target == ports.Mihomo {
		shape = "mihomo-config-fragment"
	}
	return ports.ExportDescription{ServerVersion: v, ClientWireVersion: v, Compatibility: "canonical AEAD; authorized client credential projection", ContentShape: shape}, nil
}
func (e Shadowsocks) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	o, err := module.DecodeClient(p.Options.Data)
	if err != nil {
		return nil, unsupported()
	}
	m, _ := module.Lookup(o.Method)
	if p.Validate() != nil || p.Protocol != module.Key(m.Edition) || p.Transport.Kind != "tcp" || p.Transport.Path != "" || p.Transport.Host != "" || p.TLS.Validate("none") != nil || p.UDPPayload != o.UDP || module.ValidateMaterial(o.Method, p.Credentials, true) != nil || t.Format != e.Target {
		return nil, unsupported()
	}
	name := "splicore-" + string(p.ID)
	switch e.Target {
	case ports.URI:
		if !o.UDP {
			return nil, unsupported()
		}
		value, err := module.ExportURI(module.URI{Name: name, Method: o.Method, Endpoint: p.Endpoint, Credential: p.Credentials})
		return []byte(value), err
	case ports.SingBox:
		if t.ClientVersion != "1.14.1" {
			return nil, unsupported()
		}
		value := map[string]any{"type": "shadowsocks", "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port, "method": o.Method, "password": module.Material(p.Credentials)}
		if !o.UDP {
			value["network"] = "tcp"
		}
		return json.Marshal(value)
	case ports.Mihomo:
		if t.ClientVersion != "1.19.30" {
			return nil, unsupported()
		}
		value := map[string]any{"type": "ss", "name": name, "server": p.Endpoint.Host, "port": p.Endpoint.Port, "cipher": o.Method, "password": module.Material(p.Credentials), "udp": o.UDP}
		return json.Marshal(map[string]any{"proxies": []any{value}})
	default:
		return nil, unsupported()
	}
}
