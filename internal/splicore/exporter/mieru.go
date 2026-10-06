package exporter

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/mieru"
	"strings"
)

type Mieru struct{ Target ports.Format }

func (e Mieru) Format() ports.Format { return e.Target }
func (e Mieru) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	key, ok := p.Credentials.(access.UsernamePasswordPayload)
	s, err := module.Decode(p.Options.Data)
	if !ok || err != nil || p.Validate() != nil || p.Protocol != module.Key() || p.Transport.Kind != s.Transport || p.Transport.Host != "" || p.Transport.Path != "" || p.TLS.Enabled || p.TLS.ServerName != "" || len(p.TLS.ALPN) != 0 || p.TLS.Trust != "" || p.TLS.CACertificate != "" || p.TLS.RealityPublicKey != "" || p.TLS.RealityShortID != "" || !p.UDPPayload || module.ValidateUsername(key.Username) != nil || module.ValidatePassword(key.Password) != nil || t.Format != e.Target {
		return nil, unsupported()
	}
	name := "splicore-" + string(p.ID)
	user, password := key.Username.Reveal(), key.Password.Reveal()
	multiplex := "MULTIPLEXING_" + strings.ToUpper(s.Multiplex)
	switch e.Target {
	case ports.Mieru:
		if t.ClientVersion != module.ReferenceVersion {
			return nil, unsupported()
		}
		endpoint := map[string]any{"portBindings": []any{map[string]any{"port": p.Endpoint.Port, "protocol": strings.ToUpper(s.Transport)}}}
		kind, _ := access.ParseHost(p.Endpoint.Host)
		if kind == access.DNS {
			endpoint["domainName"] = p.Endpoint.Host
		} else {
			endpoint["ipAddress"] = p.Endpoint.Host
		}
		profile := map[string]any{"profileName": name, "user": map[string]any{"name": user, "password": password}, "servers": []any{endpoint}, "mtu": s.MTU, "multiplexing": map[string]any{"level": multiplex}}
		return json.Marshal(map[string]any{"profiles": []any{profile}, "activeProfile": name})
	case ports.Mihomo:
		if t.ClientVersion != "1.19.30" || s.MTU != 1500 {
			return nil, unsupported()
		}
		return json.Marshal(map[string]any{"proxies": []any{map[string]any{"name": name, "type": "mieru", "server": p.Endpoint.Host, "port": p.Endpoint.Port, "transport": strings.ToUpper(s.Transport), "udp": true, "username": user, "password": password, "multiplexing": multiplex}}})
	default:
		return nil, unsupported()
	}
}
func (e Mieru) Describe(clientprofile.Profile) (ports.ExportDescription, error) {
	shape := "mieru-client-config"
	if e.Target == ports.Mihomo {
		shape = "mihomo-config-fragment"
	}
	return ports.ExportDescription{ServerVersion: 2, ClientWireVersion: 2, Compatibility: "official Mieru v3.38.0 default traffic pattern; Experimental", ContentShape: shape}, nil
}
