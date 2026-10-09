package api

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func clientRoute(w http.ResponseWriter, r *http.Request, q application.Queries) bool {
	if networkAPI(w, r, q) {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") || len(parts) < 1 {
		return false
	}
	resources := map[string]string{"nodes": "node", "outbounds": "outbound", "local-inbounds": "local-inbound", "local-bindings": "local-binding"}
	resource, collection := resources[parts[0]]
	if !collection && parts[0] != "client" {
		return false
	}
	allowed := ""
	if collection {
		if len(parts) == 1 {
			allowed = "GET, POST"
		} else if len(parts) == 2 {
			allowed = "GET, PUT, DELETE"
		} else if (parts[0] == "nodes" || parts[0] == "local-bindings") && len(parts) == 3 && parts[2] == "credential" {
			allowed = "POST"
		}
	} else if len(parts) == 2 {
		switch parts[1] {
		case "runtime":
			allowed = "GET"
		case "route":
			allowed = "GET, PUT"
		case "host-network":
			allowed = "GET"
		case "validate", "plan", "apply":
			allowed = "POST"
		}
	} else if len(parts) == 3 && parts[1] == "runtime" && (parts[2] == "start" || parts[2] == "stop" || parts[2] == "restart") {
		allowed = "POST"
	} else if len(parts) == 3 && parts[1] == "host-network" && parts[2] == "repair" {
		allowed = "POST"
	}
	if allowed == "" {
		writeError(w, identity.Err(identity.NotFound, "unknown client endpoint"))
		return true
	}
	methodAccepted := false
	for _, method := range strings.Split(allowed, ", ") {
		if r.Method == method {
			methodAccepted = true
		}
	}
	if !methodAccepted {
		w.Header().Set("Allow", allowed)
		writeJSON(w, 405, Problem{Code: identity.Invalid, Message: "method not allowed", RequestID: requestID()})
		return true
	}
	s, ok := q.(application.ClientCommands)
	if !ok {
		writeError(w, identity.Err(identity.NotImplemented, "client runtime unavailable"))
		return true
	}
	if r.URL.RawQuery != "" {
		writeError(w, identity.Err(identity.Invalid, "client queries are not accepted"))
		return true
	}
	if r.Method == http.MethodGet {
		status, err := s.ClientStatus(r.Context())
		if err != nil {
			writeError(w, err)
			return true
		}
		var result any
		if !collection {
			if len(parts) != 2 {
				writeError(w, identity.Err(identity.NotFound, "unknown client endpoint"))
				return true
			}
			switch parts[1] {
			case "runtime":
				result = status
			case "route":
				result = status.State.Route
			case "host-network":
				result = status.Host
			default:
				writeError(w, identity.Err(identity.NotFound, "unknown client endpoint"))
				return true
			}
		} else {
			if len(parts) > 2 {
				writeError(w, identity.Err(identity.NotFound, "unknown client endpoint"))
				return true
			}
			switch resource {
			case "node":
				result = status.State.Nodes
			case "outbound":
				result = status.State.Outbounds
			case "local-inbound":
				result = status.State.LocalInbounds
			case "local-binding":
				items := []access.Binding{}
				for _, i := range status.State.LocalInbounds {
					items = append(items, i.Bindings...)
				}
				result = items
			}
			if len(parts) == 2 {
				var found any
				switch resource {
				case "node":
					for _, n := range status.State.Nodes {
						if string(n.ID) == parts[1] {
							found = n
						}
					}
				case "outbound":
					for _, o := range status.State.Outbounds {
						if string(o.ID) == parts[1] {
							found = o
						}
					}
				case "local-binding":
					for _, i := range status.State.LocalInbounds {
						for _, b := range i.Bindings {
							if string(b.ID) == parts[1] {
								found = b
							}
						}
					}
				case "local-inbound":
					for _, i := range status.State.LocalInbounds {
						if string(i.ID) == parts[1] {
							found = i
						}
					}
				}
				if found == nil {
					writeError(w, identity.Err(identity.NotFound, "client resource not found"))
					return true
				}
				result = found
			}
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(int64(status.State.Revision), 10)+`"`)
		writeJSON(w, 200, result)
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, application.ClientDocumentLimit+1))
	if err != nil || len(body) > application.ClientDocumentLimit {
		writeError(w, identity.Err(identity.Invalid, "client request exceeds limit"))
		return true
	}
	if parts[0] == "client" && len(parts) == 2 && (parts[1] == "validate" || parts[1] == "plan" || parts[1] == "apply") {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeJSON(w, 405, Problem{Code: identity.Invalid, Message: "method not allowed", RequestID: requestID()})
			return true
		}
		var result any
		switch parts[1] {
		case "validate":
			err = s.ValidateClient(r.Context(), body)
			result = map[string]bool{"valid": true}
		case "plan":
			result, err = s.PlanClient(r.Context(), body)
		case "apply":
			var req application.ApplyRequest
			err = application.StrictClientJSON(body, &req)
			if err == nil {
				result, err = s.ApplyClient(r.Context(), req)
			}
		}
		if err != nil {
			writeError(w, err)
		} else {
			writeJSON(w, 200, result)
		}
		return true
	}
	var m application.ClientMutation
	if len(body) == 0 {
		body = []byte(`{}`)
	}
	if err = application.StrictClientJSON(body, &m); err != nil {
		writeError(w, err)
		return true
	}
	if m.Resource != "" || m.Action != "" || m.ID != "" {
		writeError(w, identity.Err(identity.Invalid, "client endpoint determines command identity"))
		return true
	}
	if collection && len(parts) == 1 && r.Method == http.MethodPost {
		m.Resource = resource
		m.Action = "create"
	} else if collection && len(parts) == 2 && (r.Method == http.MethodPut || r.Method == http.MethodDelete) {
		m.Resource = resource
		m.ID = identity.ID(parts[1])
		m.Action = "update"
		if r.Method == http.MethodDelete {
			m.Action = "delete"
		}
	} else if (parts[0] == "nodes" || parts[0] == "local-bindings") && len(parts) == 3 && parts[2] == "credential" && r.Method == http.MethodPost {
		m.Resource = resource
		m.Action = "rotate"
		m.ID = identity.ID(parts[1])
	} else if parts[0] == "client" && len(parts) == 3 && parts[1] == "host-network" && parts[2] == "repair" && r.Method == http.MethodPost {
		m.Resource = "host-network"
		m.Action = "repair"
	} else if parts[0] == "client" && len(parts) == 2 && parts[1] == "route" && r.Method == http.MethodPut {
		m.Resource = "route"
		m.Action = "update"
	} else if parts[0] == "client" && len(parts) == 3 && parts[1] == "runtime" && r.Method == http.MethodPost && (parts[2] == "start" || parts[2] == "stop" || parts[2] == "restart") {
		m.Resource = "runtime"
		m.Action = parts[2]
	} else {
		writeError(w, identity.Err(identity.Invalid, "unsupported client method or path"))
		return true
	}
	revision, err := parseClientRevision(r.Header.Get("If-Match"))
	if err != nil {
		writeError(w, err)
		return true
	}
	document, err := json.Marshal(m)
	if err != nil {
		writeError(w, identity.Err(identity.Invalid, "invalid client document"))
		return true
	}
	plan, err := s.PlanClient(r.Context(), document)
	if err != nil {
		writeError(w, err)
		return true
	}
	if plan.Revision != revision {
		writeError(w, identity.RevisionConflict(plan.Revision))
		return true
	}
	result, err := s.ApplyClient(r.Context(), application.ApplyRequest{Document: document, Digest: plan.Digest, Revision: plan.Revision})
	if err != nil {
		writeError(w, err)
	} else {
		writeJSON(w, 200, result)
	}
	return true
}
func parseClientRevision(raw string) (identity.Revision, error) {
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, identity.Err(identity.Invalid, "If-Match committed revision required")
	}
	n, err := strconv.ParseInt(raw[1:len(raw)-1], 10, 64)
	if err != nil || n < 0 {
		return 0, identity.Err(identity.Invalid, "invalid If-Match revision")
	}
	return identity.Revision(n), nil
}
