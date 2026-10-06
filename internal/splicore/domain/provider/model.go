// Package provider owns remote update sources, never runtime configurations.
package provider

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
)

const (
	MaxProviders = 64
	MaxBody      = 2 << 20
	MaxNodes     = 128
	MaxURI       = 4096
	MaxLine      = 16384
	MaxRules     = 10000
)

type Provenance struct {
	Origin     string      `json:"origin"`
	ProviderID identity.ID `json:"provider_id,omitempty"`
	Key        string      `json:"key,omitempty"`
}

func (p Provenance) Validate() error {
	if p.Origin == "" && p.ProviderID == "" && p.Key == "" {
		return nil
	}
	switch p.Origin {
	case "manual", "uri", "import":
		if p.ProviderID != "" {
			return invalid()
		}
	case "provider":
		if p.ProviderID.Validate() != nil || !identity.Label(p.Key, 128) {
			return invalid()
		}
	default:
		return invalid()
	}
	return nil
}

// Source is revealed only to the fetcher and encrypted persistence boundary.
// Even validators can echo authentication material, so they remain encrypted.
type Source struct {
	URL          string `json:"url"`
	Auth         *Auth  `json:"auth,omitempty"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}
type Auth struct {
	Type     string `json:"type"`
	Header   string `json:"header,omitempty"`
	Username string `json:"username,omitempty"`
	Value    string `json:"value"`
}

func (Source) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("Source{[REDACTED]}")) }
func (Auth) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("Auth{[REDACTED]}")) }
func ValidateURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 4096 || strings.ContainsAny(raw, "\r\n\x00") || u == nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, invalid()
	}
	if u.Port() != "" {
		if n, e := strconv.ParseUint(u.Port(), 10, 16); e != nil || n == 0 {
			return nil, invalid()
		}
	}
	return u, nil
}

// RedactURL deliberately removes all path/query/user information, including
// unknown token names. Operator names are independent display metadata.
func RedactURL(raw string) string {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" {
		return "[REDACTED]"
	}
	return u.Scheme + "://" + u.Host + "/[REDACTED]"
}
func (s Source) Validate() error {
	if _, e := ValidateURL(s.URL); e != nil {
		return e
	}
	if len(s.ETag) > 1024 || len(s.LastModified) > 128 || strings.ContainsAny(s.ETag+s.LastModified, "\r\n\x00") {
		return invalid()
	}
	if a := s.Auth; a != nil {
		if len(a.Value) == 0 || len(a.Value) > 4096 || len(a.Username) > 128 || strings.ContainsAny(a.Value+a.Username, "\r\n\x00") {
			return invalid()
		}
		switch a.Type {
		case "bearer":
			if a.Username != "" || a.Header != "" {
				return invalid()
			}
		case "basic":
			if a.Header != "" {
				return invalid()
			}
		case "header":
			if a.Username != "" || !identity.Label(a.Header, 64) {
				return invalid()
			}
			for _, c := range a.Header {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return invalid()
				}
			}
			switch strings.ToLower(a.Header) {
			case "authorization", "x-api-key":
			default:
				return invalid()
			}
		default:
			return invalid()
		}
	}
	return nil
}

type Provider struct {
	ID                identity.ID       `json:"id"`
	Name              string            `json:"name"`
	Kind              string            `json:"kind"` // proxy or ruleset, independently typed resources
	URLDisplay        string            `json:"url_display"`
	Format            string            `json:"format"`
	RefreshEnabled    bool              `json:"refresh_enabled"`
	IntervalSeconds   int               `json:"interval_seconds"`
	AllowPrivate      bool              `json:"allow_private"`
	FetchAction       P.Action          `json:"fetch_action"`
	Mode              string            `json:"mode"`
	AllowEmpty        bool              `json:"empty_is_authoritative"`
	MaxDeletePercent  int               `json:"max_delete_percent"`
	GenerateOutbounds bool              `json:"generate_outbounds"`
	Engine            string            `json:"engine,omitempty"`
	RuleSetID         identity.ID       `json:"rule_set_id,omitempty"`
	Generation        identity.Revision `json:"generation"`
	Status            string            `json:"status"`
	LastSuccess       time.Time         `json:"last_success"`
	LastFailure       time.Time         `json:"last_failure"`
	LastError         string            `json:"last_error,omitempty"`
	Failures          int               `json:"consecutive_failures"`
}

func (p *Provider) Defaults() {
	if p.IntervalSeconds == 0 {
		p.IntervalSeconds = 3600
	}
	if p.FetchAction.Kind == "" {
		p.FetchAction.Kind = P.Direct
	}
	if p.Mode == "" {
		p.Mode = "strict"
	}
	if p.MaxDeletePercent == 0 {
		p.MaxDeletePercent = 50
	}
	if p.Engine == "" && p.Kind == "proxy" {
		p.Engine = "native"
	}
	if p.Status == "" {
		p.Status = "new"
	}
}
func (p Provider) Validate() error {
	if p.ID.Validate() != nil || !identity.Label(p.Name, 128) || p.Generation < 0 || p.IntervalSeconds < 60 || p.IntervalSeconds > 86400*30 || p.FetchAction.Validate() != nil || p.FetchAction.Kind == P.Reject || p.MaxDeletePercent < 1 || p.MaxDeletePercent > 100 || p.Mode != "strict" && p.Mode != "lenient" || p.Failures < 0 || p.Failures > 10 {
		return invalid()
	}
	switch p.Status {
	case "new", "healthy", "degraded":
	default:
		return invalid()
	}
	switch p.LastError {
	case "", "fetch_failed", "parse_failed", "validation_failed", "apply_failed", "safety_guard", "revision_changed":
	default:
		return invalid()
	}
	if p.Kind == "proxy" {
		if p.RuleSetID != "" {
			return invalid()
		}
		if p.Engine != "native" {
			return identity.Err(identity.UnsupportedEngineForProtocol, "UnsupportedEngineForProtocol")
		}
		switch p.Format {
		case "auto", "uri", "base64", "canonical", "mieru", "mihomo", "sing-box":
		default:
			return invalid()
		}
	} else if p.Kind == "ruleset" {
		if p.RuleSetID.Validate() != nil || p.GenerateOutbounds || p.Engine != "" {
			return invalid()
		}
		switch p.Format {
		case "canonical-rules", "mihomo-domain", "mihomo-ipcidr", "mihomo-classical":
		default:
			return invalid()
		}
	} else {
		return invalid()
	}
	return nil
}

type State struct {
	Providers []Provider `json:"providers"`
}

func (s State) Validate() error {
	if len(s.Providers) > MaxProviders {
		return invalid()
	}
	seen := map[identity.ID]bool{}
	rules := map[identity.ID]bool{}
	for _, p := range s.Providers {
		if p.Validate() != nil || seen[p.ID] {
			return invalid()
		}
		seen[p.ID] = true
		if p.Kind == "ruleset" {
			if rules[p.RuleSetID] {
				return invalid()
			}
			rules[p.RuleSetID] = true
		}
	}
	return nil
}
func invalid() error { return identity.Err(identity.Invalid, "invalid provider intent") }
