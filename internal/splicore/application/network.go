package application

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
)

const ClientDocumentLimit = 2 << 20

func StrictManagementJSON(b []byte, v any) error { return jsonstrict.DecodeLimit(b, v, 4<<20) }

func StrictClientJSON(b []byte, v any) error {
	return jsonstrict.DecodeLimit(b, v, ClientDocumentLimit)
}

type NetworkQueries interface {
	RouteExplain(context.Context, networkruntime.Query) (networkruntime.Explanation, error)
	DNSLookup(context.Context, string) (networkruntime.DNSResult, error)
	FlushDNS(context.Context) error
}

func (s *Service) RouteExplain(_ context.Context, q networkruntime.Query) (networkruntime.Explanation, error) {
	if s.client == nil {
		return networkruntime.Explanation{}, identity.Err(identity.NotImplemented, "client runtime unavailable")
	}
	return s.client.manager.ExplainRoute(q)
}
func (s *Service) DNSLookup(ctx context.Context, domain string) (networkruntime.DNSResult, error) {
	if s.client == nil {
		return networkruntime.DNSResult{}, identity.Err(identity.NotImplemented, "client runtime unavailable")
	}
	return s.client.manager.DNSLookup(ctx, domain)
}
func (s *Service) FlushDNS(_ context.Context) error {
	if s.client == nil {
		return identity.Err(identity.NotImplemented, "client runtime unavailable")
	}
	return s.client.manager.FlushDNS()
}
func resourceMutation[T any](items []T, value *T, m ClientMutation, getID func(*T) *identity.ID) ([]T, identity.ID, error) {
	invalid := func() ([]T, identity.ID, error) {
		return nil, "", identity.Err(identity.Invalid, "invalid network resource mutation")
	}
	index := -1
	for i := range items {
		if *getID(&items[i]) == m.ID {
			index = i
		}
	}
	switch m.Action {
	case "create":
		if value == nil || m.ID != "" {
			return invalid()
		}
		v := *value
		id := getID(&v)
		if *id == "" {
			var err error
			*id, err = identity.NewID()
			if err != nil {
				return nil, "", err
			}
		}
		for i := range items {
			if *getID(&items[i]) == *id {
				return invalid()
			}
		}
		return append(items, v), *id, nil
	case "update":
		if value == nil || index < 0 || *getID(value) != m.ID {
			return invalid()
		}
		items[index] = *value
		return items, m.ID, nil
	case "delete":
		if value != nil || index < 0 {
			return invalid()
		}
		return append(items[:index], items[index+1:]...), m.ID, nil
	default:
		return invalid()
	}
}
func mutateNetwork(c *P.Config, m ClientMutation, count int, id *identity.ID) error {
	bad := func() error { return identity.Err(identity.Invalid, "invalid network command") }
	if m.Action != "delete" && count != 1 || m.Action == "delete" && count != 0 {
		return bad()
	}
	var err error
	switch m.Resource {
	case "network":
		if m.Action != "replace" || m.Network == nil || m.ID != "" {
			return bad()
		}
		*c = m.Network.Clone()
	case "route-profile":
		if m.Action != "update" || m.RouteProfile == nil || m.ID != "" {
			return bad()
		}
		c.Route = *m.RouteProfile
	case "dns-profile":
		if m.Action != "update" || m.DNSProfile == nil || m.ID != "" {
			return bad()
		}
		c.DNS = *m.DNSProfile
	case "route-rule":
		c.Route.Rules, *id, err = resourceMutation(c.Route.Rules, m.RouteRule, m, func(v *P.RouteRule) *identity.ID { return &v.ID })
	case "rule-set":
		c.RuleSets, *id, err = resourceMutation(c.RuleSets, m.RuleSet, m, func(v *P.RuleSet) *identity.ID { return &v.ID })
	case "policy-group":
		if m.Action == "select" {
			if m.Selected == nil || m.ID == "" {
				return bad()
			}
			found := false
			for i := range c.Groups {
				if c.Groups[i].ID == m.ID {
					if c.Groups[i].Type != "selector" || c.Groups[i].Selector == nil {
						return bad()
					}
					c.Groups[i].Selector = &P.SelectorSettings{Selected: *m.Selected}
					found = true
				}
			}
			if !found {
				return bad()
			}
			*id = m.ID
		} else {
			c.Groups, *id, err = resourceMutation(c.Groups, m.PolicyGroup, m, func(v *P.PolicyGroup) *identity.ID { return &v.ID })
		}
	case "dns-server":
		c.Servers, *id, err = resourceMutation(c.Servers, m.DNSServer, m, func(v *P.DNSServer) *identity.ID { return &v.ID })
	case "dns-rule":
		c.DNSRules, *id, err = resourceMutation(c.DNSRules, m.DNSRule, m, func(v *P.DNSRule) *identity.ID { return &v.ID })
	default:
		return bad()
	}
	return err
}

// MarshalNetwork is the canonical local import/export boundary, without engine JSON.
func MarshalNetwork(c P.Config) (json.RawMessage, error) { return json.Marshal(c) }
