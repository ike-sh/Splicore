package api

import (
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/networkruntime"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func networkItems(c P.Config, resource string) []any {
	out := []any{}
	switch resource {
	case "route-rule":
		for _, v := range c.Route.Rules {
			out = append(out, v)
		}
	case "rule-set":
		for _, v := range c.RuleSets {
			out = append(out, v)
		}
	case "policy-group":
		for _, v := range c.Groups {
			out = append(out, v)
		}
	case "dns-server":
		for _, v := range c.Servers {
			out = append(out, v)
		}
	case "dns-rule":
		for _, v := range c.DNSRules {
			out = append(out, v)
		}
	}
	return out
}
func networkAPI(w http.ResponseWriter, r *http.Request, q application.Queries) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	resources := map[string]string{"route-rules": "route-rule", "rule-sets": "rule-set", "policy-groups": "policy-group"}
	resource, collection := resources[parts[0]]
	if !collection && parts[0] != "routes" && parts[0] != "dns" {
		return false
	}
	s, ok := q.(application.ClientCommands)
	n, networkOK := q.(application.NetworkQueries)
	fail := func(err error) bool { writeError(w, err); return true }
	if !ok || !networkOK {
		return fail(identity.Err(identity.NotImplemented, "network runtime unavailable"))
	}
	if r.URL.RawQuery != "" {
		return fail(identity.Err(identity.Invalid, "network query parameters are not accepted"))
	}
	if parts[0] == "dns" && len(parts) >= 2 {
		resource = map[string]string{"servers": "dns-server", "rules": "dns-rule", "profile": "dns-profile"}[parts[1]]
		collection = resource != "" && resource != "dns-profile"
		if collection {
			parts = append([]string{parts[1]}, parts[2:]...)
		}
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	allowed := ""
	switch path {
	case "routes", "dns/profile":
		allowed = "GET, PUT"
	case "routes/explain", "dns/lookup", "dns/cache/flush":
		allowed = "POST"
	case "dns/cache/status", "policy-groups/status":
		allowed = "GET"
	default:
		if collection && len(parts) == 1 {
			allowed = "GET, POST"
		}
		if collection && len(parts) == 2 {
			allowed = "GET, PUT, DELETE"
		}
		if parts[0] == "policy-groups" && len(parts) == 3 && parts[2] == "select" {
			allowed = "POST"
		}
	}
	if allowed == "" {
		return fail(identity.Err(identity.NotFound, "unknown network endpoint"))
	}
	if !strings.Contains(", "+allowed+", ", ", "+r.Method+", ") {
		w.Header().Set("Allow", allowed)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	if r.Method == http.MethodGet {
		status, err := s.ClientStatus(r.Context())
		if err != nil {
			return fail(err)
		}
		var result any
		switch path {
		case "routes":
			result = status.State.Network.Route
		case "dns/profile":
			result = status.State.Network.DNS
		case "dns/cache/status":
			result = status.Network.DNS
		case "policy-groups/status":
			result = status.Network.Groups
		default:
			if !collection || len(parts) > 2 {
				return fail(identity.Err(identity.NotFound, "unknown network endpoint"))
			}
			items := networkItems(status.State.Network, resource)
			result = items
			if len(parts) == 2 {
				result = nil
				for _, item := range items {
					b, _ := json.Marshal(item)
					var id struct {
						ID string `json:"id"`
					}
					_ = json.Unmarshal(b, &id)
					if id.ID == parts[1] {
						result = item
						break
					}
				}
				if result == nil {
					return fail(identity.Err(identity.NotFound, "network resource not found"))
				}
			}
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(int64(status.State.Revision), 10)+`"`)
		writeJSON(w, 200, result)
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, application.ClientDocumentLimit+1))
	if err != nil || len(body) > application.ClientDocumentLimit {
		return fail(identity.Err(identity.Invalid, "network document exceeds limit"))
	}
	if r.Method == http.MethodPost {
		var result any
		switch path {
		case "routes/explain":
			var query networkruntime.Query
			err = application.StrictClientJSON(body, &query)
			if err == nil {
				result, err = n.RouteExplain(r.Context(), query)
			}
		case "dns/lookup":
			var query struct {
				Domain string `json:"domain"`
			}
			err = application.StrictClientJSON(body, &query)
			if err == nil {
				result, err = n.DNSLookup(r.Context(), query.Domain)
			}
		case "dns/cache/flush":
			if len(body) > 0 {
				var input struct{}
				err = application.StrictClientJSON(body, &input)
			}
			if err == nil {
				err = n.FlushDNS(r.Context())
				result = map[string]bool{"flushed": err == nil}
			}
		}
		if result != nil || err != nil {
			if err != nil {
				return fail(err)
			}
			writeJSON(w, 200, result)
			return true
		}
	}
	var m application.ClientMutation
	if len(body) == 0 {
		body = []byte(`{}`)
	}
	if err = application.StrictClientJSON(body, &m); err != nil {
		return fail(err)
	}
	if m.Resource != "" || m.Action != "" || m.ID != "" {
		return fail(identity.Err(identity.Invalid, "endpoint determines network command identity"))
	}
	switch {
	case path == "routes" && r.Method == http.MethodPut:
		m.Resource = "route-profile"
		m.Action = "update"
	case path == "dns/profile" && r.Method == http.MethodPut:
		m.Resource = "dns-profile"
		m.Action = "update"
	case collection && len(parts) == 1 && r.Method == http.MethodPost:
		m.Resource = resource
		m.Action = "create"
	case collection && len(parts) == 2 && (r.Method == http.MethodPut || r.Method == http.MethodDelete):
		m.Resource = resource
		m.ID = identity.ID(parts[1])
		m.Action = "update"
		if r.Method == http.MethodDelete {
			m.Action = "delete"
		}
	case parts[0] == "policy-groups" && len(parts) == 3 && parts[2] == "select" && r.Method == http.MethodPost:
		m.Resource = "policy-group"
		m.ID = identity.ID(parts[1])
		m.Action = "select"
	default:
		return fail(identity.Err(identity.Invalid, "unsupported network method or endpoint"))
	}
	revision, err := parseClientRevision(r.Header.Get("If-Match"))
	if err != nil {
		return fail(err)
	}
	document, _ := json.Marshal(m)
	plan, err := s.PlanClient(r.Context(), document)
	if err != nil {
		return fail(err)
	}
	if plan.Revision != revision {
		return fail(identity.RevisionConflict(plan.Revision))
	}
	result, err := s.ApplyClient(r.Context(), application.ApplyRequest{Document: document, Digest: plan.Digest, Revision: revision})
	if err != nil {
		return fail(err)
	}
	writeJSON(w, 200, result)
	return true
}
