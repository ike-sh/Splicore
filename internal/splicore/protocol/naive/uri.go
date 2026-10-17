package naive

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// URI is the established naive+https / naive+quic form. The bounded subset
// carries credentials, endpoint and display name; richer settings use config.
type URI struct {
	Mode, Name  string
	Endpoint    access.Endpoint
	Credentials access.UsernamePasswordPayload
}

func ParseURI(raw string) (URI, error) {
	var v URI
	if len(raw) > 8192 || strings.ContainsAny(raw, "\r\n\x00") {
		return v, invalid()
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User == nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.HasSuffix(u.Host, ":") {
		return v, invalid()
	}
	switch u.Scheme {
	case "naive+https":
		v.Mode = "https"
	case "naive+quic":
		v.Mode = "quic"
	default:
		return v, invalid()
	}
	password, present := u.User.Password()
	if !present {
		return v, invalid()
	}
	port := uint64(443)
	if u.Port() != "" {
		port, err = strconv.ParseUint(u.Port(), 10, 16)
	}
	v.Endpoint = access.Endpoint{Host: u.Hostname(), Port: uint16(port)}
	v.Credentials = access.UsernamePasswordPayload{Username: secret.New(u.User.Username()), Password: secret.New(password)}
	if err != nil || v.Endpoint.Validate() != nil {
		return v, invalid()
	}
	if _, err := proxy.Pair(access.Credential{Payload: v.Credentials}); err != nil {
		return v, invalid()
	}
	v.Name = u.Fragment
	if v.Name == "" {
		v.Name = "NaiveProxy"
	}
	if !identity.Label(v.Name, 128) {
		return v, invalid()
	}
	return v, nil
}
func EncodeURI(v URI) (string, error) {
	if !mode(v.Mode) || v.Endpoint.Validate() != nil || !identity.Label(v.Name, 128) {
		return "", invalid()
	}
	pair, err := proxy.Pair(access.Credential{Payload: v.Credentials})
	if err != nil {
		return "", invalid()
	}
	u := url.URL{Scheme: "naive+" + v.Mode, Host: net.JoinHostPort(v.Endpoint.Host, strconv.Itoa(int(v.Endpoint.Port))), User: url.UserPassword(pair.Username, pair.Password), Fragment: v.Name}
	return u.String(), nil
}
