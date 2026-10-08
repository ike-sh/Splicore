package exporter

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"net"
	"net/url"
	"strconv"
)

type Proxy struct{ Target ports.Format }

func (e Proxy) Describe(p clientprofile.Profile) (ports.ExportDescription, error) {
	if p.Protocol.Protocol != "socks5" && p.Protocol.Protocol != "http" {
		return ports.ExportDescription{}, unsupported()
	}
	return ports.ExportDescription{Compatibility: "RFC1928/1929 SOCKS5 or HTTP/1.1 CONNECT; cleartext proxy authentication; destination DNS follows shared policy", ContentShape: string(e.Target)}, nil
}

func (e Proxy) Format() ports.Format { return e.Target }
func (e Proxy) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	protocol := p.Protocol.Protocol
	o, err := proxy.Decode(p.Options.Data)
	if p.Validate() != nil || err != nil || p.Protocol != proxy.Key(protocol) || (protocol != "socks5" && protocol != "http") || protocol == "http" && o.UDP || p.Transport.Kind != "tcp" || p.TLS.Enabled || t.Format != e.Target {
		return nil, unsupported()
	}
	var user, pass string
	if o.Auth {
		pair, err := proxy.Pair(access.Credential{Payload: p.Credentials})
		if err != nil {
			return nil, unsupported()
		}
		user, pass = pair.Username, pair.Password
	} else {
		v, ok := p.Credentials.(access.PasswordPayload)
		if !ok || v.Password.Reveal() != proxy.NoAuth {
			return nil, unsupported()
		}
	}
	name := p.Metadata["display_name"]
	if name == "" {
		name = "splicore-" + string(p.ID)
	}
	switch e.Target {
	case ports.URI:
		if protocol == "socks5" && !o.UDP {
			return nil, unsupported()
		}
		scheme := protocol
		if scheme == "socks5" {
			scheme = "socks5h"
		}
		u := url.URL{Scheme: scheme, Host: net.JoinHostPort(p.Endpoint.Host, strconv.Itoa(int(p.Endpoint.Port))), Fragment: name}
		if o.Auth {
			u.User = url.UserPassword(user, pass)
		}
		return []byte(u.String()), nil
	case ports.SingBox:
		if t.ClientVersion != "1.14.2" {
			return nil, unsupported()
		}
		kind := protocol
		if kind == "socks5" {
			kind = "socks"
		}
		node := map[string]any{"type": kind, "tag": name, "server": p.Endpoint.Host, "server_port": p.Endpoint.Port}
		if protocol == "socks5" {
			node["version"] = "5"
			if !o.UDP {
				node["network"] = "tcp"
			}
		}
		if o.Auth {
			node["username"] = user
			node["password"] = pass
		}
		return json.Marshal(node)
	case ports.Mihomo:
		if t.ClientVersion != "1.19.32" {
			return nil, unsupported()
		}
		node := map[string]any{"type": protocol, "name": name, "server": p.Endpoint.Host, "port": p.Endpoint.Port}
		if protocol == "socks5" {
			node["udp"] = o.UDP
		}
		if o.Auth {
			node["username"] = user
			node["password"] = pass
		}
		return json.Marshal(map[string]any{"proxies": []any{node}})
	}
	return nil, unsupported()
}
