package nodeimport

import (
	"encoding/json"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	"net/netip"
	"strings"
	"unicode/utf8"
)

func ParseRules(format string, body []byte) ([]P.RuleMatch, error) {
	if len(body) > provider.MaxBody || !utf8.Valid(body) {
		return nil, invalid()
	}
	var rules []P.RuleMatch
	if format == "canonical-rules" {
		var d struct {
			Schema int           `json:"schema_version"`
			Rules  []P.RuleMatch `json:"rules"`
		}
		if jsonstrict.DecodeLimit(body, &d, provider.MaxBody) != nil || d.Schema != 1 {
			return nil, invalid()
		}
		rules = d.Rules
	} else {
		b, e := YAMLJSON(body)
		if e != nil {
			return nil, e
		}
		var d struct {
			Payload []string `json:"payload"`
		}
		if jsonstrict.DecodeLimit(b, &d, provider.MaxBody) != nil || len(d.Payload) > provider.MaxRules {
			return nil, invalid()
		}
		for _, line := range d.Payload {
			if len(line) > provider.MaxLine {
				return nil, invalid()
			}
			line = strings.TrimSpace(line)
			r := P.RuleMatch{}
			switch format {
			case "mihomo-domain":
				if strings.HasPrefix(line, "+.") {
					r.Suffixes = []string{line[2:]}
				} else if strings.HasPrefix(line, ".") {
					r.Suffixes = []string{line[1:]}
				} else {
					r.Domains = []string{line}
				}
			case "mihomo-ipcidr":
				p, e := netip.ParsePrefix(line)
				if e != nil {
					return nil, invalid()
				}
				r.CIDRs = []string{p.Masked().String()}
			case "mihomo-classical":
				parts := strings.Split(line, ",")
				if len(parts) != 2 {
					return nil, unsupported()
				}
				v := strings.TrimSpace(parts[1])
				switch strings.TrimSpace(parts[0]) {
				case "DOMAIN":
					r.Domains = []string{v}
				case "DOMAIN-SUFFIX":
					r.Suffixes = []string{v}
				case "DOMAIN-KEYWORD":
					r.Keywords = []string{v}
				case "IP-CIDR", "IP-CIDR6":
					p, e := netip.ParsePrefix(v)
					if e != nil {
						return nil, invalid()
					}
					r.CIDRs = []string{p.Masked().String()}
				default:
					return nil, unsupported()
				}
			default:
				return nil, unsupported()
			}
			rules = append(rules, r)
		}
	}
	if len(rules) > provider.MaxRules {
		return nil, invalid()
	}
	seen := map[string]bool{}
	unique := []P.RuleMatch{}
	for _, r := range rules {
		// Provider rules cannot reference mutable local resources or recursive sets.
		if len(r.LocalInbounds) != 0 || len(r.RuleSets) != 0 {
			return nil, unsupported()
		}
		b, _ := json.Marshal(r)
		if !seen[string(b)] {
			seen[string(b)] = true
			unique = append(unique, r)
		}
	}
	return unique, nil
}
