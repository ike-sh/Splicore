package exporter

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/anytls"
)

type AnyTLS struct{ Target ports.Format }

func (e AnyTLS) Format() ports.Format { return e.Target }
func (e AnyTLS) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	key, ok := p.Credentials.(access.PasswordPayload)
	o, err := module.DecodeClientOptions(p.Options.Data)
	if p.Validate() != nil || p.Protocol != module.Key() || !ok || err != nil || p.UDPPayload != o.UDP || p.Transport.Type() != "tcp" || p.Transport.ValidatePair("anytls", "tls") != nil || p.TLS.Validate("tls") != nil || t.Format != e.Target {
		return nil, unsupported()
	}
	name := p.Metadata["display_name"]
	if name == "" {
		name = "splicore-" + string(p.ID)
	}
	if e.Target == ports.URI {
		if t.ClientVersion != "" || !o.UDP || o.Version != 2 || o.IdleCheck != "30s" || o.IdleTimeout != "30s" || o.MinIdle != 0 || o.MaxSessions != 128 || o.MultiplexStreams != 1 || o.ClientMetadata != "" || o.UOTMode != "non_connect" {
			return nil, unsupported()
		}
		value, err := module.EncodeURI(module.URI{Endpoint: p.Endpoint, Password: key.Password, TLS: p.TLS, Insecure: o.Insecure, Name: name})
		return []byte(value), err
	}
	if e.Target != ports.SingBox || t.ClientVersion != "1.14.2" || o.Version != 2 || o.MaxSessions != 128 || o.MultiplexStreams != 1 || o.UOTMode != "non_connect" {
		return nil, unsupported()
	}
	tls := map[string]any{"enabled": true, "server_name": p.TLS.ServerName, "insecure": o.Insecure}
	if len(p.TLS.ALPN) > 0 {
		tls["alpn"] = p.TLS.ALPN
	}
	if p.TLS.Trust == "explicit_ca" {
		if o.Insecure {
			return nil, unsupported()
		}
		tls["certificate"] = []string{p.TLS.CACertificate}
	}
	node := map[string]any{"type": "anytls", "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port, "password": key.Password.Reveal(), "tls": tls, "idle_session_check_interval": o.IdleCheck, "idle_session_timeout": o.IdleTimeout, "min_idle_session": o.MinIdle, "client_metadata": o.ClientMetadata}
	if !o.UDP {
		node["network"] = "tcp"
	}
	return json.Marshal(node)
}
func (e AnyTLS) Describe(clientprofile.Profile) (ports.ExportDescription, error) {
	shape := "sing-box-outbound"
	if e.Target == ports.URI {
		shape = "anytls-uri"
	}
	return ports.ExportDescription{Compatibility: "native AnyTLS v2/v1; TCP and UDP-over-TCP v2; required TLS; URI supports system trust only", ContentShape: shape}, nil
}
