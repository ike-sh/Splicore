// Package streamtransport owns transport intent, independent of wire runtimes.
package streamtransport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"golang.org/x/net/http/httpguts"
)

const MaxHeaders = 16 << 10

type Config struct {
	Kind        string            `json:"kind"`
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
}

// Transport discriminators and members are exact. Null and folded aliases
// cannot erase an explicit transport selection during import or persistence.
func (c *Config) UnmarshalJSON(b []byte) error {
	type plain Config
	var fields map[string]json.RawMessage
	if len(b) > 16384 || jsonstrict.Decode(b, &fields) != nil || fields == nil {
		return bad()
	}
	allowed := map[string]bool{"kind": true, "path": true, "host": true, "headers": true, "service_name": true}
	for k, v := range fields {
		if !allowed[k] || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return bad()
		}
	}
	if _, ok := fields["kind"]; !ok {
		return bad()
	}
	var p plain
	if jsonstrict.Decode(b, &p) != nil || p.Kind == "" {
		return bad()
	}
	*c = Config(p)
	// Keep an unknown bounded discriminator as intent so canonical import can
	// preserve its typed unsupported_transport issue. Compile validation still
	// rejects it; it can never silently select raw TCP.
	switch c.Kind {
	case "tcp", "udp", "quic", "ws", "httpupgrade", "grpc":
		return c.Validate()
	default:
		if len(c.Kind) > 64 {
			return bad()
		}
		return nil
	}
}
func (c Config) Clone() Config { c.Headers = maps.Clone(c.Headers); return c }

// ValidateMember prevents a null pointer or a folded JSON alias from selecting
// raw TCP when the caller supplied an explicit server transport member.
func ValidateMember(b []byte) error {
	var fields map[string]json.RawMessage
	if jsonstrict.Decode(b, &fields) != nil {
		return bad()
	}
	for k, v := range fields {
		if strings.EqualFold(k, "stream_transport") && (k != "stream_transport" || bytes.Equal(bytes.TrimSpace(v), []byte("null"))) {
			return bad()
		}
	}
	return nil
}
func (c Config) ValidateALPN(alpn []string) error {
	if c.Type() == "tcp" || c.Type() == "udp" || c.Type() == "quic" || len(alpn) == 0 {
		return nil
	}
	want := "http/1.1"
	if c.Type() == "grpc" {
		want = "h2"
	}
	if len(alpn) != 1 || alpn[0] != want {
		return bad()
	}
	return nil
}
func (c Config) ValidateServer() error {
	if c.Validate() != nil || len(c.Headers) != 0 {
		return bad()
	}
	return nil
}

func (Config) Format(s fmt.State, _ rune) { fmt.Fprint(s, "Transport{[REDACTED]}") }
func (c Config) Type() string {
	if c.Kind == "" {
		return "tcp"
	}
	return c.Kind
}
func (c Config) HTTPPath() string {
	if c.Path == "" {
		return "/"
	}
	return c.Path
}
func (c Config) Service() string {
	if c.ServiceName == "" {
		return "GunService"
	}
	return c.ServiceName
}
func bad() error {
	return identity.Err(identity.Invalid, "invalid or unsupported shared transport settings")
}
func (c Config) Validate() error {
	switch c.Type() {
	case "tcp", "udp", "quic":
		if c.Path != "" || c.Host != "" || len(c.Headers) > 0 || c.ServiceName != "" {
			return bad()
		}
		return nil
	case "ws", "httpupgrade", "grpc":
	default:
		return bad()
	}
	if len(c.Host) > 255 || strings.IndexFunc(c.Host, unicode.IsSpace) >= 0 || strings.ContainsAny(c.Host, "/\\?#@") || strings.IndexFunc(c.Host, unicode.IsControl) >= 0 {
		return bad()
	}
	if c.Type() == "grpc" {
		if c.Path != "" || len(c.Headers) > 0 || len(c.Service()) > 128 {
			return bad()
		}
		for _, r := range c.Service() {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
				return bad()
			}
		}
		return nil
	}
	if c.ServiceName != "" || len(c.HTTPPath()) > 2048 || !strings.HasPrefix(c.HTTPPath(), "/") {
		return bad()
	}
	u, e := url.ParseRequestURI(c.HTTPPath())
	if e != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host != "" || u.IsAbs() || strings.ContainsAny(c.HTTPPath(), "?#") || strings.IndexFunc(c.HTTPPath(), unicode.IsSpace) >= 0 || strings.IndexFunc(c.HTTPPath(), unicode.IsControl) >= 0 {
		return bad()
	}
	if len(c.Headers) > 32 {
		return bad()
	}
	size := 0
	seen := map[string]bool{}
	for k, v := range c.Headers {
		key := http.CanonicalHeaderKey(k)
		lower := strings.ToLower(k)
		if !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) || strings.IndexFunc(v, unicode.IsControl) >= 0 || seen[key] {
			return bad()
		}
		if strings.HasPrefix(lower, "sec-websocket-") || strings.HasPrefix(lower, "grpc-") {
			return bad()
		}
		switch lower {
		case "host", "connection", "upgrade", "content-length", "transfer-encoding", "authorization", "proxy-authorization", "cookie", "te", "trailer":
			return bad()
		}
		seen[key] = true
		size += len(k) + len(v) + 4
	}
	if size > MaxHeaders/2 {
		return bad()
	}
	return nil
}

// ValidatePair is deliberately narrower than ecosystem possibilities. Existing
// REALITY and Vision retain their raw-stream contract; no fallback is allowed.
func (c Config) ValidatePair(protocol, security string) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if c.Type() == "tcp" {
		return nil
	}
	if c.Type() != "ws" && c.Type() != "httpupgrade" && c.Type() != "grpc" {
		return bad()
	}
	if protocol != "vmess" && protocol != "vless" && protocol != "trojan" {
		return bad()
	}
	if security != "none" && security != "tls" || protocol == "trojan" && security != "tls" {
		return bad()
	}
	return nil
}
