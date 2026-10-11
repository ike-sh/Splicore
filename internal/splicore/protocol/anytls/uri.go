package anytls

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
	Insecure bool
	Name     string
}

func (URI) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("AnyTLSURI{[REDACTED]}")) }
func ParseURI(raw string) (URI, error) {
	var v URI
	if len(raw) > 4096 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\r\n\x00") {
		return v, invalid()
	}
	authority := strings.TrimPrefix(raw, "anytls://")
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority = authority[:i]
	}
	if strings.Count(authority, "@") != 1 {
		return v, invalid()
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "anytls" || u.Opaque != "" || u.User == nil || u.Path != "" && u.Path != "/" || u.Host == "" || strings.Contains(u.Host, "@") {
		return v, invalid()
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return v, invalid()
	}
	if credential.ValidatePassword(secret.New(u.User.Username())) != nil {
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
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return v, invalid()
	}
	for key, values := range query {
		if len(values) != 1 {
			return v, invalid()
		}
		if key != "sni" && key != "insecure" {
			return v, identity.Err(identity.UnsupportedExport, "unsupported AnyTLS URI parameter")
		}
	}
	sni := query.Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}
	if _, err := access.ParseHost(sni); err != nil {
		return v, invalid()
	}
	if value, ok := query["insecure"]; ok {
		if value[0] != "0" && value[0] != "1" {
			return v, invalid()
		}
		v.Insecure = value[0] == "1"
	}
	v.TLS = access.ClientTLS{Enabled: true, ServerName: sni, Trust: "system"}
	if v.TLS.Validate("tls") != nil {
		return v, invalid()
	}
	v.Name = u.Fragment
	if v.Name == "" {
		v.Name = "Imported AnyTLS node"
	}
	if !identity.Label(v.Name, 128) {
		return v, invalid()
	}
	v.Password = secret.New(u.User.Username())
	return v, nil
}
func EncodeURI(v URI) (string, error) {
	if v.Endpoint.Validate() != nil || credential.ValidatePassword(v.Password) != nil || v.TLS.Validate("tls") != nil || v.TLS.Trust != "system" || v.TLS.CACertificate != "" || len(v.TLS.ALPN) != 0 || !identity.Label(v.Name, 128) {
		return "", identity.Err(identity.UnsupportedExport, "AnyTLS URI cannot represent configuration")
	}
	if _, err := access.ParseHost(v.TLS.ServerName); err != nil {
		return "", invalid()
	}
	q := url.Values{"sni": {v.TLS.ServerName}}
	if v.Insecure {
		q.Set("insecure", "1")
	}
	u := url.URL{Scheme: "anytls", User: url.User(v.Password.Reveal()), Host: net.JoinHostPort(v.Endpoint.Host, strconv.Itoa(int(v.Endpoint.Port))), Path: "/", RawQuery: q.Encode(), Fragment: v.Name}
	return u.String(), nil
}
