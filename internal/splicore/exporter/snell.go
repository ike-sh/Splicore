// Package exporter encodes explicitly authorized client projections.
package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"strconv"
	"strings"
)

type Snell struct{ Target ports.Format }

func (e Snell) Describe(p clientprofile.Profile) (ports.ExportDescription, error) {
	s, err := snell.DecodeClient(p.Options.Data)
	if err != nil {
		return ports.ExportDescription{}, unsupported()
	}
	v, _ := snell.ClientVersion(s.Version)
	compat := "exact"
	if s.Version == 5 {
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
	s, err := snell.DecodeClient(p.Options.Data)
	k, ok := p.Credentials.(access.PSKPayload)
	udp := s.UDP == nil || *s.UDP
	if err != nil || !ok || snell.ValidatePSK(k.Key) != nil || p.Protocol != snell.Key(s.Version) || p.UDPPayload != udp || p.TLS.Enabled || p.Transport.Kind != "tcp" || p.Transport.Path != "" || p.Transport.Host != "" {
		return nil, unsupported()
	}
	if t.Format != e.Target {
		return nil, unsupported()
	}
	v, _ := snell.ClientVersion(s.Version) // Explicit canonical compatibility mapping.
	name := "splicore-" + string(p.ID)
	psk := k.Key.Reveal()
	switch e.Target {
	case ports.Mihomo:
		if (t.ClientVersion != "1.19.30" && t.ClientVersion != "1.19.32") || (s.Version != 4 && s.Version != 5) || s.ObfsURI != "" && s.ObfsURI != "/" || s.UDPPort != 0 {
			return nil, unsupported()
		}
		// JSON is a YAML subset accepted by the pinned Mihomo parser.
		node := map[string]any{"name": name, "type": "snell", "server": p.Endpoint.Host, "port": p.Endpoint.Port, "psk": psk, "version": v, "udp": udp}
		if s.Version == 4 {
			node["reuse"] = s.Reuse
			if s.ObfsMode == "http" {
				node["obfs-opts"] = map[string]string{"mode": "http", "host": s.HTTPHost()}
			}
		}
		return json.Marshal(node)
	case ports.SingBox:
		if (t.ClientVersion != "1.14.1" && t.ClientVersion != "1.14.3") || s.ObfsURI != "" && s.ObfsURI != "/" || s.UDPPort != 0 {
			return nil, unsupported()
		}
		node := map[string]any{"type": "snell", "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port, "psk": psk, "version": v}
		if s.Version == 4 {
			node["reuse"] = s.Reuse
			if !udp {
				node["network"] = "tcp"
			}
			if s.ObfsMode == "http" {
				node["obfs_mode"] = "http"
				node["obfs_host"] = s.HTTPHost()
			}
		}
		return json.Marshal(node)
	case ports.Surge:
		if !udp {
			return nil, unsupported()
		}
		if t.ClientVersion != "mac-6.7.0" && t.ClientVersion != "ios-5.20.0" {
			return nil, unsupported()
		}
		// Surge's comma-separated hostname slot accepts a raw IPv6 literal, with port separate.
		// Hosts are canonical validated IP/DNS values; PSKs are restricted above.
		line := fmt.Sprintf("%s = snell, %s, %s, psk=%s, version=%d", name, p.Endpoint.Host, strconv.Itoa(int(p.Endpoint.Port)), psk, v)
		if s.Version == 4 {
			line += fmt.Sprintf(", reuse=%t", s.Reuse)
			if s.ObfsMode == "http" {
				if strings.ContainsAny(s.HTTPURI(), ",=\"") {
					return nil, unsupported()
				}
				line += ", obfs=http, obfs-host=" + s.HTTPHost() + ", obfs-uri=" + s.HTTPURI()
			}
			if s.UDPPort != 0 {
				line += fmt.Sprintf(", udp-port=%d", s.UDPPort)
			}
		}
		return []byte(line), nil
	default:
		return nil, unsupported()
	}
}
