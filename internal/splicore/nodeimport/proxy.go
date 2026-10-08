package nodeimport

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	httpproxy "github.com/ike-sh/Splicore/internal/splicore/protocol/http"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"net/url"
	"strings"
)

func proxyCandidate(protocol, name string, endpoint access.Endpoint, user, pass string, auth, udp bool) (Candidate, error) {
	if endpoint.Validate() != nil || protocol == "http" && udp {
		return Candidate{}, invalid()
	}
	c := Candidate{Node: client.RemoteNode{Name: name, Protocol: proxy.Key(protocol), Endpoint: endpoint, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}}}
	if c.Node.Name == "" {
		c.Node.Name = protocol + " proxy"
	}
	o, _ := json.Marshal(proxy.Options{Auth: auth, UDP: udp})
	c.Node.Options = client.Options{Schema: 1, Data: o}
	if auth {
		pair := socks5.Credentials{Username: user, Password: pass}
		if pair.Validate() != nil || strings.ContainsAny(user, ":\x00\r\n") || strings.ContainsAny(pass, "\x00\r\n") {
			return Candidate{}, invalid()
		}
		raw, _ := json.Marshal(map[string]string{"username": user, "password": pass})
		c.Credential = Credential{Kind: access.UsernamePassword, Value: string(raw)}
	} else {
		if user != "" || pass != "" {
			return Candidate{}, invalid()
		}
		c.Credential = Credential{Kind: access.Password, Value: proxy.NoAuth}
	}
	return c, nil
}
func parseProxyURI(raw string) (Candidate, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
		return Candidate{}, invalid()
	}
	protocol := "socks5"
	if u.Scheme == "http" {
		protocol = "http"
	}
	endpoint, e := httpproxy.Authority(u.Host)
	if e != nil {
		return Candidate{}, invalid()
	}
	user, pass := "", ""
	auth := u.User != nil
	if auth {
		user = u.User.Username()
		var ok bool
		pass, ok = u.User.Password()
		if !ok {
			return Candidate{}, invalid()
		}
	}
	return proxyCandidate(protocol, u.Fragment, endpoint, user, pass, auth, protocol == "socks5")
}
func externalProxy(format string, raw []byte) (Candidate, error) {
	var n struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		Tag        string `json:"tag"`
		Server     string `json:"server"`
		Port       uint16 `json:"port"`
		ServerPort uint16 `json:"server_port"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		UDP        *bool  `json:"udp"`
		Network    string `json:"network"`
		Version    string `json:"version"`
	}
	if jsonstrict.Decode(raw, &n) != nil {
		return Candidate{}, unsupported()
	}
	protocol := n.Type
	if protocol == "socks" {
		protocol = "socks5"
	}
	if protocol != "http" && protocol != "socks5" {
		return Candidate{}, unsupported()
	}
	if n.Version != "" && n.Version != "5" || n.Network != "" && n.Network != "tcp" {
		return Candidate{}, unsupported()
	}
	port, name := n.Port, n.Name
	if format == "sing-box" {
		if n.Port != 0 || n.Name != "" || n.Type == "socks5" {
			return Candidate{}, unsupported()
		}
		port, name = n.ServerPort, n.Tag
	} else if n.ServerPort != 0 || n.Tag != "" || n.Version != "" {
		return Candidate{}, unsupported()
	}
	udp := protocol == "socks5"
	if n.Network == "tcp" {
		udp = false
	}
	if n.UDP != nil {
		udp = *n.UDP
	}
	return proxyCandidate(protocol, name, access.Endpoint{Host: n.Server, Port: port}, n.Username, n.Password, n.Username != "" || n.Password != "", udp)
}
