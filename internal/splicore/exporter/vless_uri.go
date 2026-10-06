package exporter

import (
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type VLESSURI struct {
	Endpoint   access.Endpoint
	UUID       secret.Value
	Security   module.Security
	Flow       module.Flow
	ServerName string
	PublicKey  module.PublicKey
	ShortID    module.ShortID
	Name       string
}

func (VLESSURI) Format(s fmt.State, v rune) { _, _ = s.Write([]byte("VLESSURI{[REDACTED]}")) }
func renderVLESSURI(p clientprofile.Profile, c access.UUIDPayload, o module.ClientOptions) ([]byte, error) {
	if module.ValidateFlow(o.Flow) != nil {
		return nil, unsupported()
	}
	q := url.Values{"encryption": {"none"}, "type": {"tcp"}, "security": {string(o.Security)}, "packetEncoding": {"xudp"}}
	if o.Security == module.Reality {
		q.Set("sni", p.TLS.ServerName)
		q.Set("pbk", p.TLS.RealityPublicKey)
		q.Set("sid", p.TLS.RealityShortID)
		q.Set("fp", "chrome")
	}
	u := url.URL{Scheme: "vless", User: url.User(c.UUID.Reveal()), Host: net.JoinHostPort(p.Endpoint.Host, strconv.Itoa(int(p.Endpoint.Port))), RawQuery: q.Encode(), Fragment: "splicore-" + string(p.ID)}
	return []byte(u.String()), nil
}

// ParseVLESSURI accepts the bounded exported dialect; unknown extensions fail closed.
// Explicit CA TLS cannot be represented faithfully by this URI and is unsupported.
func ParseVLESSURI(s string) (VLESSURI, error) {
	var out VLESSURI
	if len(s) > 4096 || strings.ContainsAny(s, "\r\n\x00") {
		return out, unsupported()
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "vless" || u.User == nil || u.Path != "" || u.Opaque != "" {
		return out, unsupported()
	}
	if _, present := u.User.Password(); present {
		return out, unsupported()
	}
	out.UUID = secret.New(u.User.Username())
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return out, unsupported()
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	out.Endpoint = access.Endpoint{Host: u.Hostname(), Port: uint16(port)}
	if err != nil || out.Endpoint.Validate() != nil || module.ValidateUUID(out.UUID) != nil {
		return out, unsupported()
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return out, unsupported()
	}
	allowed := map[string]bool{"encryption": true, "type": true, "security": true, "packetEncoding": true, "flow": true, "sni": true, "pbk": true, "sid": true, "fp": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			return out, unsupported()
		}
	}
	if q.Get("encryption") != "none" || q.Get("type") != "tcp" || q.Get("packetEncoding") != "xudp" {
		return out, unsupported()
	}
	out.Security = module.Security(q.Get("security"))
	out.Flow = module.NoFlow
	if f := q.Get("flow"); f != "" {
		out.Flow = module.Flow(f)
	}
	if module.ValidateFlow(out.Flow) != nil {
		return out, unsupported()
	}
	if out.Security == module.Plain {
		if out.Flow != module.NoFlow {
			return out, unsupported()
		}
		for _, k := range []string{"sni", "pbk", "sid", "fp"} {
			if _, ok := q[k]; ok {
				return out, unsupported()
			}
		}
	} else if out.Security == module.Reality {
		out.ServerName = q.Get("sni")
		out.PublicKey = module.PublicKey(q.Get("pbk"))
		out.ShortID = module.ShortID(q.Get("sid"))
		kind, err := access.ParseHost(out.ServerName)
		if err != nil || kind != access.DNS || module.ValidatePublicKey(out.PublicKey) != nil || q.Get("fp") != "chrome" {
			return out, unsupported()
		}
		if _, err := module.ParseShortID(out.ShortID); err != nil {
			return out, unsupported()
		}
		if _, ok := q["sid"]; !ok {
			return out, unsupported()
		}
	} else {
		return out, unsupported()
	}
	if u.Fragment != "" && !identity.Label(u.Fragment, 128) {
		return out, unsupported()
	}
	out.Name = u.Fragment
	return out, nil
}
