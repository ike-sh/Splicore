package shadowsocks

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
)

type URI struct {
	Name, Method string
	Endpoint     access.Endpoint
	Credential   access.Payload
}

func (URI) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("ShadowsocksURI{[REDACTED]}")) }
func decode64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding.Strict(), base64.URLEncoding.Strict(), base64.RawStdEncoding.Strict(), base64.StdEncoding.Strict()} {
		if b, e := enc.DecodeString(s); e == nil {
			return b, nil
		}
	}
	return nil, invalid()
}
func ParseURI(raw string) (URI, error) {
	var out URI
	if len(raw) > 8192 || !utf8.ValidString(raw) || !strings.HasPrefix(raw, "ss://") || strings.ContainsAny(raw, " \t\r\n\x00") {
		return out, invalid()
	}
	legacy := false
	if !strings.Contains(strings.SplitN(raw, "#", 2)[0], "@") {
		parts := strings.SplitN(strings.TrimPrefix(raw, "ss://"), "#", 2)
		b, e := decode64(parts[0])
		if e != nil || !utf8.Valid(b) || !strings.Contains(string(b), "@") {
			return out, invalid()
		}
		userinfo, authority, ok := strings.Cut(string(b), "@")
		if !ok || strings.Contains(authority, "@") {
			return out, invalid()
		}
		method, password, ok := strings.Cut(userinfo, ":")
		if !ok {
			return out, invalid()
		}
		raw = "ss://" + url.UserPassword(method, password).String() + "@" + authority
		if len(parts) == 2 {
			raw += "#" + parts[1]
		}
		legacy = true
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "ss" || u.Opaque != "" || u.User == nil || u.RawQuery != "" || u.ForceQuery || u.Path != "" && u.Path != "/" {
		return out, invalid()
	}
	method, password := u.User.Username(), ""
	encoded := false
	if p, ok := u.User.Password(); ok {
		password = p
	} else {
		b, e := decode64(method)
		if e != nil || !utf8.Valid(b) {
			return out, invalid()
		}
		var ok bool
		method, password, ok = strings.Cut(string(b), ":")
		if !ok {
			return out, invalid()
		}
		encoded = true
	}
	m, e := Lookup(method)
	if e != nil {
		return out, e
	}
	if strings.IndexFunc(password, unicode.IsControl) >= 0 {
		return out, invalid()
	}
	if m.Edition == "2022" && (legacy || encoded) {
		return out, invalid()
	}
	port, e := strconv.ParseUint(u.Port(), 10, 16)
	if e != nil || port == 0 {
		return out, invalid()
	}
	endpoint := access.Endpoint{Host: u.Hostname(), Port: uint16(port)}
	if endpoint.Validate() != nil {
		return out, invalid()
	}
	var payload access.Payload = access.PasswordPayload{Password: secret.New(password)}
	if m.Edition == "2022" {
		payload = access.PSKPayload{Key: secret.New(password)}
	}
	if e = ValidateMaterial(method, payload, true); e != nil {
		return out, e
	}
	name := u.Fragment
	if name == "" {
		name = "Imported node"
	}
	if !identity.Label(name, 128) {
		return out, invalid()
	}
	return URI{Name: name, Method: method, Endpoint: endpoint, Credential: payload}, nil
}
func ExportURI(v URI) (string, error) {
	m, e := Lookup(v.Method)
	if e != nil || v.Endpoint.Validate() != nil || ValidateMaterial(v.Method, v.Credential, true) != nil || !identity.Label(v.Name, 128) {
		return "", identity.Err(identity.UnsupportedExport, "unsupported shadowsocks URI projection")
	}
	var user *url.Userinfo
	if strings.IndexFunc(Material(v.Credential), unicode.IsControl) >= 0 {
		return "", identity.Err(identity.UnsupportedExport, "unsupported shadowsocks URI credential")
	}
	if m.Edition == "2022" {
		user = url.UserPassword(v.Method, Material(v.Credential))
	} else {
		user = url.User(base64.RawURLEncoding.EncodeToString([]byte(v.Method + ":" + Material(v.Credential))))
	}
	u := url.URL{Scheme: "ss", User: user, Host: net.JoinHostPort(v.Endpoint.Host, strconv.Itoa(int(v.Endpoint.Port))), Fragment: v.Name}
	return u.String(), nil
}
