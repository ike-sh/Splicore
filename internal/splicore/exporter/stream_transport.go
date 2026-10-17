package exporter

import (
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func streamProjection(p clientprofile.Profile, format ports.Format, n map[string]any) error {
	c := p.Transport
	security := "none"
	if p.TLS.Enabled {
		security = "tls"
	}
	if p.Protocol.FeatureProfile == "reality" {
		security = "reality"
	}
	if c.ValidatePair(p.Protocol.Protocol, security) != nil {
		return unsupported()
	}
	if c.Type() == "tcp" {
		return nil
	}
	if c.Type() == "mkcp" {
		if format != ports.Xray {
			return unsupported()
		}
		s, ok := n["streamSettings"].(map[string]any)
		if !ok {
			return unsupported()
		}
		s["network"], s["kcpSettings"] = "kcp", c.MKCPSettings()
		return nil
	}
	if c.Type() == "xhttp" {
		if format != ports.Xray {
			return unsupported()
		}
		s, ok := n["streamSettings"].(map[string]any)
		if !ok {
			return unsupported()
		}
		opts, e := xhttpProjection(c)
		if e != nil {
			return e
		}
		s["network"] = "xhttp"
		s["xhttpSettings"] = opts
		return nil
	}
	headers := map[string]string{}
	for k, v := range c.Headers {
		headers[k] = v
	}
	switch format {
	case ports.SingBox:
		tr := map[string]any{"type": c.Type()}
		switch c.Type() {
		case "ws":
			tr["path"] = c.HTTPPath()
			if c.Host != "" {
				headers["Host"] = c.Host
			}
			if len(headers) > 0 {
				tr["headers"] = headers
			}
		case "httpupgrade":
			tr["path"] = c.HTTPPath()
			if c.Host != "" {
				tr["host"] = c.Host
			}
			if len(headers) > 0 {
				tr["headers"] = headers
			}
		case "grpc":
			if c.Host != "" {
				return unsupported()
			}
			tr["service_name"] = c.Service()
		}
		n["transport"] = tr
	case ports.Mihomo:
		if c.Type() == "grpc" {
			if c.Host != "" {
				return unsupported()
			}
			n["network"] = "grpc"
			n["grpc-opts"] = map[string]any{"grpc-service-name": c.Service()}
		} else {
			n["network"] = "ws"
			opts := map[string]any{"path": c.HTTPPath()}
			if c.Host != "" {
				headers["Host"] = c.Host
			}
			if len(headers) > 0 {
				opts["headers"] = headers
			}
			if c.Type() == "httpupgrade" {
				opts["v2ray-http-upgrade"] = true
			}
			n["ws-opts"] = opts
		}
	case ports.Xray:
		s, ok := n["streamSettings"].(map[string]any)
		if !ok {
			return unsupported()
		}
		kind := c.Type()
		if kind == "ws" {
			kind = "ws"
		}
		s["network"] = kind
		opts := map[string]any{}
		if kind == "grpc" {
			opts["serviceName"] = c.Service()
			if c.Host != "" {
				opts["authority"] = c.Host
			}
			s["grpcSettings"] = opts
		} else {
			opts["path"] = c.HTTPPath()
			if c.Host != "" {
				opts["host"] = c.Host
			}
			if len(headers) > 0 {
				opts["headers"] = headers
			}
			key := "wsSettings"
			if kind == "httpupgrade" {
				key = "httpupgradeSettings"
			}
			s[key] = opts
		}
	default:
		return unsupported()
	}
	return nil
}
