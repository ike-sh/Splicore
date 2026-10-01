package exporter

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
)

type Hysteria2 struct{ Target ports.Format }

func (e Hysteria2) Format() ports.Format { return e.Target }
func (e Hysteria2) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	key, ok := p.Credentials.(access.PasswordPayload)
	var options map[string]json.RawMessage
	if p.Validate() != nil || p.Protocol != module.Key() || !ok || module.ValidatePassword(key.Password) != nil || !p.UDPPayload || p.Transport.Kind != "quic" || p.Transport.Path != "" || p.Transport.Host != "" || !p.TLS.Enabled || p.TLS.Trust != "explicit_ca" || p.TLS.ServerName == "" || len(p.TLS.ALPN) != 1 || p.TLS.ALPN[0] != "h3" || p.TLS.RealityPublicKey != "" || p.TLS.RealityShortID != "" || json.Unmarshal(p.Options.Data, &options) != nil || options == nil || len(options) != 0 || t.Format != e.Target {
		return nil, unsupported()
	}
	if _, err := module.CAPool(p.TLS.CACertificate); err != nil {
		return nil, unsupported()
	}
	if _, err := access.ParseHost(p.TLS.ServerName); err != nil {
		return nil, unsupported()
	}
	name := "splicore-" + string(p.ID)
	password := key.Password.Reveal()
	switch e.Target {
	case ports.Mihomo:
		if t.ClientVersion != "1.19.30" {
			return nil, unsupported()
		}
		pin, err := module.CAFingerprint(p.TLS.CACertificate)
		if err != nil {
			return nil, unsupported()
		}
		node := map[string]any{"name": name, "type": "hysteria2", "server": p.Endpoint.Host, "port": p.Endpoint.Port, "password": password, "sni": p.TLS.ServerName, "skip-cert-verify": false, "alpn": []string{"h3"}, "fingerprint": pin}
		// A non-leaf CA pin preserves full chain/SNI verification and avoids the
		// pinned client's global CA-pool reset after proxy construction.
		return json.Marshal(map[string]any{"proxies": []any{node}})
	case ports.SingBox:
		if t.ClientVersion != "1.14.1" {
			return nil, unsupported()
		}
		return json.Marshal(map[string]any{"type": "hysteria2", "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port, "password": password, "tls": map[string]any{"enabled": true, "server_name": p.TLS.ServerName, "insecure": false, "alpn": []string{"h3"}, "certificate": []string{p.TLS.CACertificate}}})
	default:
		return nil, unsupported()
	}
}
func (e Hysteria2) Describe(p clientprofile.Profile) (ports.ExportDescription, error) {
	shape := "sing-box-outbound"
	if e.Target == ports.Mihomo {
		shape = "mihomo-config-fragment"
	}
	return ports.ExportDescription{ServerVersion: 2, ClientWireVersion: 2, Compatibility: "exact; certificate verification required", ContentShape: shape}, nil
}
