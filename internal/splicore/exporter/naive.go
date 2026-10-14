package exporter

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/naive"
)

type Naive struct{ Target ports.Format }

func (e Naive) Format() ports.Format { return e.Target }
func (e Naive) Describe(clientprofile.Profile) (ports.ExportDescription, error) {
	return ports.ExportDescription{Compatibility: "Native Naive H2/H3 TCP CONNECT; URI preserves system trust only; richer settings require canonical config; Chromium fingerprint parity not claimed", ContentShape: "naive-uri"}, nil
}
func (e Naive) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	pair, ok := p.Credentials.(access.UsernamePasswordPayload)
	o, err := module.DecodeClient(p.Options.Data)
	if p.Validate() != nil || p.Protocol != module.Key() || !ok || err != nil || p.UDPPayload || p.Transport.Kind != module.Carrier(o.Mode) ||
		p.Transport.Path != "" || p.Transport.Host != "" || len(p.Transport.Headers) != 0 || p.Transport.FinalMask != nil || p.Transport.XHTTP != nil || p.Transport.ServiceName != "" ||
		p.TLS.Validate("tls") != nil || p.TLS.Trust != "system" || p.TLS.ServerName != p.Endpoint.Host || p.TLS.CACertificate != "" ||
		len(p.TLS.ALPN) > 0 && (len(p.TLS.ALPN) != 1 || p.TLS.ALPN[0] != module.ALPN(o.Mode)) ||
		e.Target != ports.URI || t.Format != ports.URI || t.ClientVersion != "" || o.Padding != "auto" || o.MaxConnections != 1 || o.MaxStreams != 128 ||
		len(o.ExtraHeaders) != 0 || o.ConnectTimeout != "" || o.TunnelTimeout != "" || o.IdleTimeout != "" || o.CongestionControl != "" {
		return nil, unsupported()
	}
	name := p.Metadata["display_name"]
	if name == "" {
		name = "splicore-" + string(p.ID)
	}
	value, err := module.EncodeURI(module.URI{Mode: o.Mode, Name: name, Endpoint: p.Endpoint, Credentials: pair})
	return []byte(value), err
}
