package nodeimport

import (
	"bytes"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"net/http"
	"strings"
)

// Normalize only researched transport fields, then reuse the original strict
// protocol parser. Neither aliases nor duplicate members are lost by rewriting.
func extractStream(format string, b []byte) ([]byte, cfg.Config, error) {
	c := cfg.Config{Kind: "tcp"}
	modified := false
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return nil, c, invalid()
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	if _, e := vm.Object(b, names, false); e != nil {
		return nil, c, e
	}
	var typ string
	if json.Unmarshal(fields["type"], &typ) != nil {
		return b, c, nil
	}
	if typ != "vmess" && typ != "vless" && typ != "trojan" {
		return b, c, nil
	}
	if format == "mihomo" && typ == "vless" {
		if raw, ok := fields["tls"]; ok {
			var enabled bool
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &enabled) != nil {
				return nil, c, invalid()
			}
			if _, alias := fields["servername"]; alias {
				if _, conflict := fields["sni"]; conflict {
					return nil, c, invalid()
				}
				fields["sni"] = fields["servername"]
				delete(fields, "servername")
			}
			if !enabled {
				for _, name := range []string{"sni", "alpn", "reality-opts", "client-fingerprint", "fingerprint"} {
					if _, exists := fields[name]; exists {
						return nil, c, unsupported()
					}
				}
			} else if _, ok := fields["sni"]; !ok {
				fields["sni"] = fields["server"]
			}
			if enabled {
				var name string
				if json.Unmarshal(fields["sni"], &name) != nil || name == "" {
					return nil, c, invalid()
				}
			}
			delete(fields, "tls")
			modified = true
		}
		if raw, ok := fields["packet-encoding"]; ok {
			var value string
			if json.Unmarshal(raw, &value) != nil || value != "xudp" {
				return nil, c, unsupported()
			}
			delete(fields, "packet-encoding")
			modified = true
		}
	}
	if format == "sing-box" {
		if raw, ok := fields["transport"]; ok {
			if _, e := vm.Object(raw, []string{"type", "path", "host", "headers", "service_name"}, false); e != nil {
				return nil, c, e
			}
			var w struct {
				Type    string            `json:"type"`
				Path    string            `json:"path"`
				Host    string            `json:"host"`
				Headers map[string]string `json:"headers"`
				Service string            `json:"service_name"`
			}
			if jsonstrict.Decode(raw, &w) != nil {
				return nil, c, unsupported()
			}
			c = cfg.Config{Kind: w.Type, Path: w.Path, Host: w.Host, Headers: w.Headers, ServiceName: w.Service}
			if c.Kind != "ws" && c.Kind != "httpupgrade" && c.Kind != "grpc" {
				return nil, c, unsupported()
			}
			delete(fields, "transport")
		}
	} else {
		var kind string
		if raw, ok := fields["network"]; ok && json.Unmarshal(raw, &kind) != nil {
			return nil, c, unsupported()
		}
		if kind != "" && kind != "tcp" {
			switch kind {
			case "ws":
				var w struct {
					Path        string            `json:"path"`
					Headers     map[string]string `json:"headers"`
					Upgrade     bool              `json:"v2ray-http-upgrade"`
					Fast        bool              `json:"v2ray-http-upgrade-fast-open"`
					Early       int               `json:"max-early-data"`
					EarlyHeader string            `json:"early-data-header-name"`
				}
				if raw, ok := fields["ws-opts"]; ok {
					if _, e := vm.Object(raw, []string{"path", "headers", "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open", "max-early-data", "early-data-header-name"}, false); e != nil {
						return nil, c, e
					}
					if jsonstrict.Decode(raw, &w) != nil || w.Fast || w.Early != 0 || w.EarlyHeader != "" {
						return nil, c, unsupported()
					}
				}
				c = cfg.Config{Kind: "ws", Path: w.Path, Headers: w.Headers}
				if w.Upgrade {
					c.Kind = "httpupgrade"
				}
				delete(fields, "ws-opts")
			case "grpc":
				var w struct {
					Service string `json:"grpc-service-name"`
				}
				if raw, ok := fields["grpc-opts"]; ok {
					if _, e := vm.Object(raw, []string{"grpc-service-name"}, false); e != nil {
						return nil, c, e
					}
					if jsonstrict.Decode(raw, &w) != nil {
						return nil, c, unsupported()
					}
				}
				c = cfg.Config{Kind: "grpc", ServiceName: w.Service}
				delete(fields, "grpc-opts")
			default:
				return nil, c, vm.Unsupported("unsupported_transport")
			}
			fields["network"] = json.RawMessage(`""`)
		}
		if _, ok := fields["ws-opts"]; ok {
			return nil, c, unsupported()
		}
		if _, ok := fields["grpc-opts"]; ok {
			return nil, c, unsupported()
		}
	}
	// Both ecosystems express WS Host as a custom header. It is a distinct
	// authority field internally; conflicting spellings fail closed.
	seen := map[string]bool{}
	for k, v := range c.Headers {
		key := http.CanonicalHeaderKey(k)
		if seen[key] {
			return nil, c, invalid()
		}
		seen[key] = true
		if strings.EqualFold(k, "Host") {
			if c.Host != "" && c.Host != v {
				return nil, c, invalid()
			}
			c.Host = v
			delete(c.Headers, k)
		}
	}
	if len(c.Headers) == 0 {
		c.Headers = nil
	}
	if c.Validate() != nil {
		return nil, c, vm.Unsupported("unsupported_transport")
	}
	if c.Type() == "tcp" && !modified {
		return b, c, nil
	}
	normalized, e := json.Marshal(fields)
	return normalized, c, e
}

func externalVMess(format string, b []byte) (Candidate, error) {
	raw, transport, e := extractStream(format, b)
	if e != nil {
		return Candidate{}, e
	}
	c, e := externalVMessBase(format, raw)
	if e != nil {
		return c, e
	}
	if transport.ValidatePair("vmess", c.Node.Security.Kind) != nil {
		return c, vm.Unsupported("unsupported_transport")
	}
	c.Node.Transport = client.Transport(transport)
	return c, nil
}
