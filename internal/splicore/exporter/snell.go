// Package exporter encodes explicitly authorized client projections.
package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"strconv"
)

type Snell struct{ Target ports.Format }

func (e Snell) Describe(p clientprofile.Profile) (ports.ExportDescription, error) {
	s, err := snell.Decode(p.Options.Data)
	if err != nil {
		return ports.ExportDescription{}, unsupported()
	}
	v, compat := s.Version, "exact"
	if v == 5 {
		v = 4
		compat = "v4 TCP/UDP client to v5 server; QUIC Proxy Mode unavailable"
	}
	shape := "sing-box-outbound"
	if e.Target == ports.Mihomo {
		shape = "mihomo-node"
	}
	if e.Target == ports.Surge {
		shape = "surge-declaration"
	}
	return ports.ExportDescription{ServerVersion: s.Version, ClientWireVersion: v, Compatibility: compat, ContentShape: shape}, nil
}

func (e Snell) Format() ports.Format { return e.Target }
func unsupported() error {
	return identity.Err(identity.UnsupportedExport, "UnsupportedExport: client version or protocol feature not supported")
}
func (e Snell) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	if p.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "invalid client projection")
	}
	s, err := snell.Decode(p.Options.Data)
	k, ok := p.Credentials.(access.PSKPayload)
	if err != nil || !ok || snell.ValidatePSK(k.Key) != nil || p.Protocol != snell.Key(s.Version) || !p.UDPPayload || p.TLS.Enabled || p.Transport.Kind != "tcp" || p.Transport.Path != "" || p.Transport.Host != "" {
		return nil, unsupported()
	}
	if t.Format != e.Target {
		return nil, unsupported()
	}
	v := s.Version
	if v == 5 {
		v = 4
	} // Explicit compatibility mapping is returned by the application export envelope.
	name := "splicore-" + string(p.ID)
	psk := k.Key.Reveal()
	switch e.Target {
	case ports.Mihomo:
		if t.ClientVersion != "1.19.30" || s.Version != 5 {
			return nil, unsupported()
		}
		// JSON is a YAML subset accepted by the pinned Mihomo parser.
		return json.Marshal(map[string]any{"name": name, "type": "snell", "server": p.Endpoint.Host, "port": p.Endpoint.Port, "psk": psk, "version": v, "udp": true})
	case ports.SingBox:
		if t.ClientVersion != "1.14.1" {
			return nil, unsupported()
		}
		return json.Marshal(map[string]any{"type": "snell", "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port, "psk": psk, "version": v})
	case ports.Surge:
		if t.ClientVersion != "mac-6.7.0" && t.ClientVersion != "ios-5.20.0" {
			return nil, unsupported()
		}
		// Surge's comma-separated hostname slot accepts a raw IPv6 literal, with port separate.
		// Hosts are canonical validated IP/DNS values; PSKs are restricted above.
		return []byte(fmt.Sprintf("%s = snell, %s, %s, psk=%s, version=%d", name, p.Endpoint.Host, strconv.Itoa(int(p.Endpoint.Port)), psk, v)), nil
	default:
		return nil, unsupported()
	}
}
