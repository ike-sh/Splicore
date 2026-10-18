package hysteria2

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

type URI struct {
	Endpoint  access.Endpoint
	Password  secret.Value
	TLS       access.ClientTLS
	Transport cfg.Config
	Name      string
}

func (URI) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("HysteriaURI{[REDACTED]}")) }
func uriUnsupported() error {
	return identity.Err(identity.UnsupportedExport, "Hysteria2 URI cannot represent configuration")
}

// net/url deliberately rejects nonnumeric ports. Parse the bounded multi-port
// authority first, then delegate escaping, userinfo and query parsing to net/url.
func ParseURI(raw string) (URI, error) {
	var v URI
	if len(raw) > 4096 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\r\n\x00") {
		return v, invalid()
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || scheme != "hy2" && scheme != "hysteria2" {
		return v, invalid()
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	if strings.Count(authority, "@") != 1 {
		return v, invalid()
	}
	user, hostport, _ := strings.Cut(authority, "@")
	host, ports := hostport, "443"
	if strings.HasPrefix(hostport, "[") {
		closing := strings.IndexByte(hostport, ']')
		if closing < 0 {
			return v, invalid()
		}
		host = hostport[1:closing]
		tail := hostport[closing+1:]
		if tail != "" {
			if !strings.HasPrefix(tail, ":") {
				return v, invalid()
			}
			ports = tail[1:]
		}
	} else if strings.Contains(hostport, ":") {
		var e error
		host, ports, e = net.SplitHostPort(hostport)
		if e != nil {
			return v, invalid()
		}
	}
	set, e := cfg.ParseHysteriaPorts(ports)
	if e != nil {
		return v, invalid()
	}
	u, e := url.Parse(scheme + "://" + user + "@" + net.JoinHostPort(host, "443") + rest[end:])
	if e != nil || u.User == nil || u.Opaque != "" || u.Path != "" && u.Path != "/" {
		return v, invalid()
	}
	v.Endpoint = access.Endpoint{Host: host, Port: set.First()}
	if v.Endpoint.Validate() != nil {
		return v, invalid()
	}
	password := u.User.Username()
	if p, ok := u.User.Password(); ok {
		password += ":" + p
	}
	v.Password = secret.New(password)
	if len(password) == 0 || len(password) > 1024 {
		return URI{}, invalid()
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return URI{}, invalid()
	}
	for k, values := range q {
		if len(values) != 1 {
			return URI{}, invalid()
		}
		switch k {
		case "sni", "insecure", "obfs", "obfs-password":
		default:
			return URI{}, uriUnsupported()
		}
	}
	if q.Has("insecure") && q.Get("insecure") != "0" {
		return URI{}, uriUnsupported()
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = host
	}
	if _, e := access.ParseHost(sni); e != nil {
		return URI{}, invalid()
	}
	v.TLS = access.ClientTLS{Enabled: true, ServerName: sni, Trust: "system", ALPN: []string{"h3"}}
	h := cfg.Hysteria{Version: 2}
	if q.Has("obfs") {
		h.Obfs = &cfg.HysteriaObfs{Type: q.Get("obfs"), Password: q.Get("obfs-password")}
		if h.Obfs.Type == "none" || h.Obfs.Validate() != nil {
			return URI{}, invalid()
		}
	} else if q.Has("obfs-password") {
		return URI{}, invalid()
	}
	if set.Len() > 1 || strings.ContainsAny(ports, ",-") {
		h.UDP = &cfg.HysteriaUDP{Ports: set.String()}
	}
	v.Transport = cfg.Config{Kind: "hysteria"}
	if h.Obfs != nil || h.UDP != nil {
		v.Transport.Hysteria = &h
	}
	v.Name = u.Fragment
	if v.Name == "" {
		v.Name = "Imported node"
	}
	if !identity.Label(v.Name, 128) {
		return URI{}, invalid()
	}
	return v, nil
}

func EncodeURI(v URI) (string, error) {
	if v.Endpoint.Validate() != nil || ValidatePassword(v.Password) != nil || v.Transport.ValidatePair("hysteria2", "tls") != nil || !v.TLS.Enabled || v.TLS.Trust != "system" || v.TLS.CACertificate != "" || v.TLS.RealityPublicKey != "" || v.TLS.RealityShortID != "" || len(v.TLS.ALPN) != 1 || v.TLS.ALPN[0] != "h3" || !identity.Label(v.Name, 128) {
		return "", uriUnsupported()
	}
	if _, e := access.ParseHost(v.TLS.ServerName); e != nil {
		return "", uriUnsupported()
	}
	h := v.Transport.HysteriaSettings()
	q := url.Values{"sni": {v.TLS.ServerName}}
	ports := strconv.Itoa(int(v.Endpoint.Port))
	if h.UDP != nil {
		u := h.UDP
		if u.HopInterval != 0 || u.MinHopInterval != 0 || u.MaxHopInterval != 0 || u.ServerPortRange != "" {
			return "", uriUnsupported()
		}
		set, e := cfg.ParseHysteriaPorts(u.Ports)
		if e != nil {
			return "", uriUnsupported()
		}
		ports = set.String()
		h.UDP = nil
	}
	if h.Obfs != nil {
		o := h.Obfs
		if o.MinPacketSize != 0 || o.MaxPacketSize != 0 {
			return "", uriUnsupported()
		}
		if o.Type != "none" {
			q.Set("obfs", o.Type)
			q.Set("obfs-password", o.Password)
		}
		h.Obfs = nil
	}
	if h != (cfg.Hysteria{Version: 2}) {
		return "", uriUnsupported()
	}
	u := url.URL{Scheme: "hysteria2", User: url.User(v.Password.Reveal()), Host: net.JoinHostPort(v.Endpoint.Host, ports), Path: "/", RawQuery: q.Encode(), Fragment: v.Name}
	return u.String(), nil
}
