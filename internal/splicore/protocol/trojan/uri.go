package trojan

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
)

type URI struct {
	Endpoint access.Endpoint
	Password secret.Value
	TLS      access.ClientTLS
	Name     string
}

func (URI) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("TrojanURI{[REDACTED]}")) }
func ParseURI(raw string) (URI, error) {
	var v URI
	if len(raw) > 4096 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\x00\r\n") {
		return v, invalid()
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "trojan" || u.Opaque != "" || u.User == nil || u.Path != "" && u.Path != "/" || strings.Count(u.Host, "@") != 0 {
		return v, invalid()
	}
	// Raw authority permits one delimiter. Literal password @ must be escaped.
	authority := strings.SplitN(strings.TrimPrefix(raw, "trojan://"), "/", 2)[0]
	if end := strings.IndexAny(authority, "?#"); end >= 0 {
		authority = authority[:end]
	}
	if strings.Count(authority, "@") != 1 {
		return v, invalid()
	}
	pass := u.User.Username()
	if p, ok := u.User.Password(); ok {
		pass += ":" + p
	}
	if credential.ValidatePassword(secret.New(pass)) != nil {
		return v, invalid()
	}
	port := uint64(443)
	if u.Port() != "" {
		port, err = strconv.ParseUint(u.Port(), 10, 16)
	}
	if err != nil || port == 0 {
		return v, invalid()
	}
	v.Endpoint = access.Endpoint{Host: u.Hostname(), Port: uint16(port)}
	if v.Endpoint.Validate() != nil {
		return v, invalid()
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return v, invalid()
	}
	for k, values := range q {
		if len(values) != 1 {
			return v, invalid()
		}
		switch k {
		case "sni", "peer", "alpn", "security", "type", "allowInsecure", "insecure":
		default:
			return v, identity.Err(identity.UnsupportedExport, "unsupported Trojan URI parameter")
		}
	}
	if q.Get("security") != "" && q.Get("security") != "tls" || q.Get("type") != "" && q.Get("type") != "tcp" || q.Get("insecure") != "" && q.Get("insecure") != "0" || q.Get("allowInsecure") != "" && q.Get("allowInsecure") != "0" {
		return v, identity.Err(identity.UnsupportedExport, "unsupported Trojan URI security or transport")
	}
	if q.Get("sni") != "" && q.Get("peer") != "" {
		return v, invalid()
	}
	name := q.Get("sni")
	if name == "" {
		name = q.Get("peer")
	}
	if name == "" {
		name = u.Hostname()
	}
	v.TLS = access.ClientTLS{Enabled: true, ServerName: name, Trust: "system"}
	if _, err := access.ParseHost(name); err != nil {
		return URI{}, invalid()
	}
	if values, ok := q["alpn"]; ok {
		v.TLS.ALPN = strings.Split(values[0], ",")
	}
	if v.TLS.Validate("tls") != nil {
		return URI{}, invalid()
	}
	v.Name = u.Fragment
	if v.Name == "" {
		v.Name = "Imported Trojan node"
	}
	if !identity.Label(v.Name, 128) {
		return URI{}, invalid()
	}
	v.Password = secret.New(pass)
	return v, nil
}
func EncodeURI(v URI) (string, error) {
	if v.Endpoint.Validate() != nil || credential.ValidatePassword(v.Password) != nil || v.TLS.Validate("tls") != nil || v.TLS.Trust != "system" || v.TLS.CACertificate != "" || !identity.Label(v.Name, 128) {
		return "", identity.Err(identity.UnsupportedExport, "Trojan URI cannot represent configuration")
	}
	q := url.Values{"sni": {v.TLS.ServerName}}
	for _, token := range v.TLS.ALPN {
		if strings.Contains(token, ",") {
			return "", identity.Err(identity.UnsupportedExport, "Trojan URI cannot represent ALPN")
		}
	}
	if len(v.TLS.ALPN) > 0 {
		q.Set("alpn", strings.Join(v.TLS.ALPN, ","))
	}
	u := url.URL{Scheme: "trojan", User: url.User(v.Password.Reveal()), Host: net.JoinHostPort(v.Endpoint.Host, strconv.Itoa(int(v.Endpoint.Port))), RawQuery: q.Encode(), Fragment: v.Name}
	return u.String(), nil
}
