// Package nodeimport parses bounded client definitions into canonical candidates.
// It never creates runtime adapters, persists data or prints secret input.
package nodeimport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/exporter"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	hm "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	tm "github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	vm "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
)

type Credential struct {
	Kind  access.CredentialKind `json:"kind"`
	Value string                `json:"value"`
}

func (Credential) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[REDACTED]")) }

type Candidate struct {
	Engine     string            `json:"engine,omitempty"` // import annotation only; never selects a runtime
	Origin     string            `json:"-"`                // assigned only by parser, never by import JSON
	Key        string            `json:"key,omitempty"`
	Node       client.RemoteNode `json:"node"`
	Credential Credential        `json:"credential"`
}

func (Candidate) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("Candidate{[REDACTED]}")) }

type Document struct {
	Schema int         `json:"schema_version"`
	Nodes  []Candidate `json:"nodes"`
}
type Issue struct {
	Index int    `json:"index"`
	Kind  string `json:"kind"`
	Code  string `json:"code"`
}
type Result struct {
	Candidates []Candidate
	Issues     []Issue
}

func invalid() error { return identity.Err(identity.Invalid, "invalid bounded import document") }
func unsupported() error {
	return identity.Err(identity.UnsupportedExport, "unsupported import capability")
}
func Parse(format string, body []byte) (Result, error) {
	var out Result
	if len(body) > provider.MaxBody || !utf8.Valid(body) {
		return out, invalid()
	}
	text := strings.TrimSpace(string(body))
	if format == "auto" {
		switch {
		case strings.HasPrefix(text, "{"):
			format = "canonical"
		case strings.Contains(text, "://"):
			format = "uri"
		default:
			return out, unsupported()
		}
	}
	switch format {
	case "canonical":
		var d struct {
			Schema int               `json:"schema_version"`
			Nodes  []json.RawMessage `json:"nodes"`
		}
		if jsonstrict.DecodeLimit(body, &d, provider.MaxBody) != nil || d.Schema != 1 || len(d.Nodes) > provider.MaxNodes {
			return out, invalid()
		}
		for i, raw := range d.Nodes {
			if retiredCapability(raw) {
				out.Issues = append(out.Issues, Issue{i + 1, "Unsupported", "outside_splicore_runtime"})
				continue
			}
			var c Candidate
			if jsonstrict.DecodeLimit(raw, &c, provider.MaxBody) != nil {
				return out, invalid()
			}
			if c.Engine != "" && c.Engine != "native" {
				out.Issues = append(out.Issues, Issue{i + 1, "Unsupported", "unsupported_engine"})
				continue
			}
			out.Candidates = append(out.Candidates, c)
		}
	case "base64":
		if len(text) > provider.MaxBody {
			return out, invalid()
		}
		b, e := base64.StdEncoding.Strict().DecodeString(text)
		if e != nil {
			b, e = base64.RawStdEncoding.Strict().DecodeString(text)
		}
		if e != nil || len(b) > provider.MaxBody {
			return out, invalid()
		}
		return Parse("uri", b)
	case "uri":
		lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
		if len(lines) > provider.MaxNodes+1 {
			return out, invalid()
		}
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if len(line) > provider.MaxURI {
				return out, invalid()
			}
			c, e := ParseURI(line)
			if e != nil {
				kind := "Invalid"
				code := "invalid_uri"
				if e == errUnsupported {
					kind = "Unsupported"
					code = "unsupported_uri"
				}
				out.Issues = append(out.Issues, Issue{i + 1, kind, code})
			} else {
				c.Origin = "uri"
				out.Candidates = append(out.Candidates, c)
			}
		}
	case "mieru":
		return parseMieru(body)
	case "mihomo", "sing-box":
		return parseExternal(format, body)
	default:
		return out, unsupported()
	}
	for i, c := range out.Candidates {
		if c.Node.ID != "" || c.Node.CredentialID != "" || c.Node.Provenance != (provider.Provenance{}) || c.Node.State != "" || c.Key != "" && !identity.Label(c.Key, 120) || !identity.Label(c.Node.Name, 128) || len(c.Credential.Value) > 16384 {
			out.Issues = append(out.Issues, Issue{i + 1, "Invalid", "invalid_candidate"})
		}
	}
	return out, nil
}

var errUnsupported = unsupported()

func ParseURI(raw string) (Candidate, error) {
	var c Candidate
	if len(raw) > provider.MaxURI || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\r\n\x00") {
		return c, invalid()
	}
	u, e := url.Parse(raw)
	if e != nil || u.Opaque != "" {
		return c, invalid()
	}
	switch u.Scheme {
	case "mieru", "mierus":
		return parseMieruURI(raw)
	case "tuic":
		if u.User == nil || u.Path != "" {
			return c, invalid()
		}
		password, ok := u.User.Password()
		if !ok {
			return c, errUnsupported
		}
		port, e := strconv.ParseUint(u.Port(), 10, 16)
		if e != nil || port == 0 {
			return c, invalid()
		}
		q, e := url.ParseQuery(u.RawQuery)
		if e != nil {
			return c, invalid()
		}
		for k, v := range q {
			if len(v) != 1 {
				return c, invalid()
			}
			switch k {
			case "sni", "alpn", "congestion_control", "udp_relay_mode", "disable_sni":
			default:
				return c, errUnsupported
			}
		}
		if q.Get("congestion_control") != "" && q.Get("congestion_control") != "cubic" || q.Get("udp_relay_mode") != "" && q.Get("udp_relay_mode") != "native" || q.Get("disable_sni") != "" && q.Get("disable_sni") != "0" || q.Get("alpn") != "" && q.Get("alpn") != "h3" {
			return c, errUnsupported
		}
		sni := q.Get("sni")
		if sni == "" {
			sni = u.Hostname()
		}
		options, _ := json.Marshal(tm.ClientOptions{Version: 5, CongestionControl: "cubic", UDPRelayMode: "native"})
		c.Node = client.RemoteNode{Name: u.Fragment, Protocol: tm.Key(), Endpoint: access.Endpoint{Host: u.Hostname(), Port: uint16(port)}, Transport: client.Transport{Kind: "quic"}, Security: client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: sni, Trust: "system", ALPN: []string{"h3"}}}, Options: client.Options{Schema: 1, Data: options}}
		pair, _ := json.Marshal(map[string]string{"uuid": u.User.Username(), "password": password})
		c.Credential = Credential{access.UUIDPassword, string(pair)}
	case "vless":
		v, e := exporter.ParseVLESSURI(raw)
		if e != nil {
			return c, errUnsupported
		}
		c.Node = client.RemoteNode{Name: v.Name, Protocol: vm.Key(v.Security), Endpoint: v.Endpoint, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: string(v.Security)}, Options: client.Options{Schema: 1}}
		c.Node.Options.Data, _ = json.Marshal(vm.ClientOptions{Security: v.Security, Flow: v.Flow, PacketEncoding: "xudp"})
		if v.Security == vm.Reality {
			c.Node.Security.TLS = access.ClientTLS{Enabled: true, ServerName: v.ServerName, Trust: "reality", RealityPublicKey: string(v.PublicKey), RealityShortID: string(v.ShortID)}
		}
		c.Credential = Credential{access.UUID, v.UUID.Reveal()}
	case "hy2", "hysteria2":
		if u.User == nil || u.Path != "" && u.Path != "/" {
			return c, invalid()
		}
		port := uint64(443)
		if u.Port() != "" {
			port, e = strconv.ParseUint(u.Port(), 10, 16)
		}
		if e != nil || port == 0 {
			return c, invalid()
		}
		q, e := url.ParseQuery(u.RawQuery)
		if e != nil {
			return c, invalid()
		}
		for k, v := range q {
			if len(v) != 1 {
				return c, invalid()
			}
			switch k {
			case "sni", "insecure":
			default:
				return c, errUnsupported
			}
		}
		if q.Get("insecure") != "" && q.Get("insecure") != "0" {
			return c, errUnsupported
		}
		password := u.User.Username()
		if p, ok := u.User.Password(); ok {
			password += ":" + p
		}
		sni := q.Get("sni")
		if sni == "" {
			sni = u.Hostname()
		}
		c.Node = client.RemoteNode{Name: u.Fragment, Protocol: hm.Key(), Endpoint: access.Endpoint{Host: u.Hostname(), Port: uint16(port)}, Transport: client.Transport{Kind: "quic"}, Security: client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: sni, Trust: "system", ALPN: []string{"h3"}}}, Options: client.Options{Schema: 1, Data: json.RawMessage(`{}`)}}
		c.Credential = Credential{access.Password, password}
	default:
		return c, errUnsupported
	}
	if c.Node.Name == "" {
		c.Node.Name = "Imported node"
	}
	if !identity.Label(c.Node.Name, 128) || c.Node.Endpoint.Validate() != nil {
		return Candidate{}, invalid()
	}
	return c, nil
}
