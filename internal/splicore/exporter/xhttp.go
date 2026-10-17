package exporter

import (
	"encoding/json"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

func xhttpProjection(c cfg.Config) (map[string]any, error) {
	if c.Type() != "xhttp" || c.Validate() != nil {
		return nil, unsupported()
	}
	x := cfg.XHTTP{}
	if c.XHTTP != nil {
		x = *c.XHTTP
	}
	d := x.Download
	x.Download = nil
	b, e := json.Marshal(x)
	if e != nil {
		return nil, e
	}
	var opts map[string]any
	_ = json.Unmarshal(b, &opts)
	opts["path"] = c.HTTPPath()
	if c.Host != "" {
		opts["host"] = c.Host
	}
	if len(c.Headers) > 0 {
		opts["headers"] = c.Headers
	}
	if d != nil {
		next, e := xhttpProjection(d.Transport)
		if e != nil {
			return nil, e
		}
		leg := xraySecurity(d.Security, d.TLS)
		leg["address"] = d.Endpoint.Host
		leg["port"] = d.Endpoint.Port
		leg["network"] = "xhttp"
		leg["xhttpSettings"] = next
		opts["downloadSettings"] = leg
	}
	return opts, nil
}
func xraySecurity(kind string, t access.ClientTLS) map[string]any {
	s := map[string]any{"security": kind}
	if kind == "tls" {
		settings := map[string]any{"serverName": t.ServerName, "allowInsecure": false}
		if len(t.ALPN) > 0 {
			settings["alpn"] = t.ALPN
		}
		if len(t.ALPN) == 1 && t.ALPN[0] == "http/1.1" {
			// The pinned reference's default Chrome hello advertises H2 even for
			// H1 transport selection. Use its standard TLS hello with H1 ALPN;
			// certificate verification stays enabled.
			settings["fingerprint"] = "unsafe"
		}
		if t.Trust == "explicit_ca" {
			settings["certificates"] = []any{map[string]any{"usage": "verify", "certificate": strings.Split(strings.TrimSpace(t.CACertificate), "\n")}}
		}
		s["tlsSettings"] = settings
	} else if kind == "reality" {
		s["realitySettings"] = map[string]any{"serverName": t.ServerName, "password": t.RealityPublicKey, "shortId": t.RealityShortID, "fingerprint": "chrome"}
	}
	return s
}
