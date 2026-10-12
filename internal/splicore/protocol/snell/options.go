package snell

import (
	"bytes"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"net/url"
	"strings"
)

// ClientOptions is the explicit v4 policy over the common Snell wire.
// Absent UDP preserves the existing enabled UDP contract.
type ClientOptions struct {
	Version  int    `json:"version"`
	Reuse    bool   `json:"reuse,omitempty"`
	UDP      *bool  `json:"udp,omitempty"`
	UDPPort  uint16 `json:"udp_port,omitempty"`
	ObfsMode string `json:"obfs_mode,omitempty"`
	ObfsHost string `json:"obfs_host,omitempty"`
	ObfsURI  string `json:"obfs_uri,omitempty"`
}

func strictOptions(b []byte, v any) error {
	if jsonstrict.DecodeLimit(b, v, 16384) != nil {
		return invalid()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil {
		return invalid()
	}
	for _, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return invalid()
		}
	}
	for name := range fields {
		allowed := name == "version" || name == "obfs_mode"
		if _, client := v.(*ClientOptions); client {
			allowed = allowed || name == "reuse" || name == "udp" || name == "udp_port" || name == "obfs_host" || name == "obfs_uri"
		}
		if !allowed {
			return invalid()
		}
	}
	return nil
}

func DecodeClient(b []byte) (ClientOptions, error) {
	var s ClientOptions
	if strictOptions(b, &s) != nil {
		return s, invalid()
	}
	if s.Version != 4 {
		base, e := Decode(b)
		return ClientOptions{Version: base.Version}, e
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	if _, ok := fields["udp_port"]; ok && s.UDPPort == 0 {
		return s, invalid()
	}
	if s.UDP != nil && !*s.UDP && s.UDPPort != 0 {
		return s, invalid()
	}
	if ValidateObfs(s.ObfsMode, s.ObfsHost, s.ObfsURI) != nil {
		return s, invalid()
	}
	return s, nil
}

func ValidateObfs(mode, host, uri string) error {
	if mode != "" && mode != "none" && mode != "http" {
		return invalid()
	}
	if mode != "http" {
		if host != "" || uri != "" {
			return invalid()
		}
		return nil
	}
	if host != "" && (access.Endpoint{Host: host, Port: 80}).Validate() != nil {
		return invalid()
	}
	if uri != "" {
		if len(uri) > 2048 || !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
			return invalid()
		}
		for _, c := range []byte(uri) {
			if c <= 32 || c >= 127 {
				return invalid()
			}
		}
		u, e := url.ParseRequestURI(uri)
		if e != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" || strings.Contains(uri, "#") {
			return invalid()
		}
	}
	return nil
}

func (s ClientOptions) HTTPHost() string {
	if s.ObfsHost == "" {
		return "localhost"
	}
	return s.ObfsHost
}
func (s ClientOptions) HTTPURI() string {
	if s.ObfsURI == "" {
		return "/"
	}
	return s.ObfsURI
}
