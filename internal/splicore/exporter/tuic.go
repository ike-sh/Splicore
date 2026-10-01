package exporter

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/credential"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	"github.com/sagernet/sing-box/internal/splicore/tlsconfig"
)

type TUIC struct{ Target ports.Format }

func (e TUIC) Format() ports.Format { return e.Target }
func (e TUIC) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	key, ok := p.Credentials.(access.UUIDPasswordPayload)
	o, optionErr := module.DecodeClientOptions(p.Options.Data)
	kind, err := access.ParseHost(p.TLS.ServerName)
	if p.Validate() != nil || p.Protocol != module.Key() || !ok || module.ValidateUUID(key.UUID) != nil || credential.ValidatePassword(key.Password) != nil || !p.UDPPayload || p.Transport.Kind != "quic" || p.Transport.Path != "" || p.Transport.Host != "" || !p.TLS.Enabled || p.TLS.Trust != "explicit_ca" || err != nil || kind != access.DNS || len(p.TLS.ALPN) != 1 || p.TLS.ALPN[0] != "h3" || p.TLS.RealityPublicKey != "" || p.TLS.RealityShortID != "" || optionErr != nil || o.Version != 5 || o.CongestionControl != "cubic" || o.UDPRelayMode != "native" || o.ZeroRTT || t.Format != e.Target {
		return nil, unsupported()
	}
	if _, err := tlsconfig.CAPool(p.TLS.CACertificate); err != nil {
		return nil, unsupported()
	}
	name := "splicore-" + string(p.ID)
	switch e.Target {
	case ports.Mihomo:
		if t.ClientVersion != "1.19.30" {
			return nil, unsupported()
		}
		pin, _ := tlsconfig.CAFingerprint(p.TLS.CACertificate)
		return json.Marshal(map[string]any{"proxies": []any{map[string]any{"name": name, "type": "tuic", "server": p.Endpoint.Host, "port": p.Endpoint.Port, "uuid": key.UUID.Reveal(), "password": key.Password.Reveal(), "sni": p.TLS.ServerName, "skip-cert-verify": false, "alpn": []string{"h3"}, "fingerprint": pin, "reduce-rtt": false, "udp-relay-mode": "native", "congestion-controller": "cubic", "heartbeat-interval": 10000}}})
	case ports.SingBox:
		if t.ClientVersion != "1.14.1" {
			return nil, unsupported()
		}
		return json.Marshal(map[string]any{"type": "tuic", "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port, "uuid": key.UUID.Reveal(), "password": key.Password.Reveal(), "congestion_control": "cubic", "udp_relay_mode": "native", "zero_rtt_handshake": false, "heartbeat": "10s", "tls": map[string]any{"enabled": true, "server_name": p.TLS.ServerName, "insecure": false, "alpn": []string{"h3"}, "certificate": []string{p.TLS.CACertificate}}})
	default:
		return nil, unsupported()
	}
}
func (e TUIC) Describe(p clientprofile.Profile) (ports.ExportDescription, error) {
	shape := "sing-box-outbound"
	if e.Target == ports.Mihomo {
		shape = "mihomo-config-fragment"
	}
	return ports.ExportDescription{ServerVersion: 5, ClientWireVersion: 5, Compatibility: "exact; certificate verification required", ContentShape: shape}, nil
}
