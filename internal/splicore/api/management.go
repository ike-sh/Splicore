package api

import (
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"io"
	"net/http"
	"strings"
)

func managementRoute(w http.ResponseWriter, r *http.Request, q application.Queries) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	collection := parts[0] == "providers" || parts[0] == "rule-set-providers"
	special := parts[0] == "imports" || parts[0] == "nodes" && len(parts) == 2 && (parts[1] == "import-preview" || parts[1] == "batch-preview" || parts[1] == "export")
	if !collection && !special {
		return false
	}
	s, ok := q.(application.ManagementCommands)
	if !ok {
		writeError(w, identity.Err(identity.NotImplemented, "management unavailable"))
		return true
	}
	if r.URL.RawQuery != "" {
		writeError(w, identity.Err(identity.Invalid, "management query unsupported"))
		return true
	}
	if collection && r.Method == "GET" && len(parts) <= 2 {
		c, ok := q.(application.ClientCommands)
		if !ok {
			writeError(w, identity.Err(identity.NotImplemented, "client unavailable"))
			return true
		}
		status, e := c.ClientStatus(r.Context())
		if e != nil {
			writeError(w, e)
			return true
		}
		kind := "proxy"
		if parts[0] == "rule-set-providers" {
			kind = "ruleset"
		}
		items := []provider.Provider{}
		for _, p := range status.State.Management.Providers {
			if p.Kind == kind && (len(parts) == 1 || string(p.ID) == parts[1]) {
				items = append(items, p)
			}
		}
		if len(parts) == 2 {
			if len(items) != 1 {
				writeError(w, identity.Err(identity.NotFound, "provider not found"))
			} else {
				writeJSON(w, 200, items[0])
			}
		} else {
			writeJSON(w, 200, items)
		}
		return true
	}
	allowed := r.Method == "POST" && (special && len(parts) == 2 || collection && len(parts) == 1 || collection && len(parts) == 3 && (parts[2] == "refresh" || parts[2] == "refresh-preview")) || collection && len(parts) == 2 && (r.Method == "PUT" || r.Method == "DELETE")
	if !allowed {
		writeJSON(w, 405, Problem{Code: identity.Invalid, Message: "method not allowed", RequestID: requestID()})
		return true
	}
	if collection && len(parts) >= 2 {
		c, ok := q.(application.ClientCommands)
		if !ok {
			writeError(w, identity.Err(identity.NotImplemented, "client unavailable"))
			return true
		}
		status, err := c.ClientStatus(r.Context())
		if err != nil {
			writeError(w, err)
			return true
		}
		kind := "proxy"
		if parts[0] == "rule-set-providers" {
			kind = "ruleset"
		}
		found := false
		for _, p := range status.State.Management.Providers {
			found = found || string(p.ID) == parts[1] && p.Kind == kind
		}
		if !found {
			writeError(w, identity.Err(identity.NotFound, "provider not found"))
			return true
		}
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
	if e != nil || len(body) > 4<<20 {
		writeError(w, identity.Err(identity.Invalid, "management request limit"))
		return true
	}
	if len(body) == 0 {
		body = []byte(`{}`)
	}
	var result any
	switch {
	case parts[0] == "imports" && parts[1] == "apply":
		var req application.ManagementApply
		e = application.StrictManagementJSON(body, &req)
		if e == nil {
			result, e = s.ApplyManagement(r.Context(), req)
		}
	case parts[0] == "nodes" && parts[1] == "export":
		var req application.NodeExportRequest
		e = application.StrictManagementJSON(body, &req)
		if e == nil {
			result, e = s.ExportNodes(r.Context(), req)
		}
	case collection && len(parts) == 3:
		var req struct{}
		e = application.StrictManagementJSON(body, &req)
		if e == nil {
			if parts[2] == "refresh-preview" {
				result, e = s.PreviewProviderRefresh(r.Context(), identity.ID(parts[1]))
			} else {
				result, e = s.RefreshProvider(r.Context(), identity.ID(parts[1]))
			}
		}
	default:
		var req application.ManagementRequest
		e = application.StrictManagementJSON(body, &req)
		if e == nil {
			if collection {
				if req.Operation != "" || req.ID != "" {
					e = identity.Err(identity.Invalid, "endpoint determines identity")
				} else {
					req.Operation = "provider-upsert"
					if len(parts) == 2 {
						req.ID = identity.ID(parts[1])
					}
					if r.Method == "DELETE" {
						req.Operation = "provider-delete"
					}
					kind := "proxy"
					if parts[0] == "rule-set-providers" {
						kind = "ruleset"
					}
					if req.Provider != nil && req.Provider.Kind != kind {
						e = identity.Err(identity.Invalid, "provider kind mismatch")
					}
				}
			} else if parts[0] == "nodes" {
				op := "import"
				if parts[1] == "batch-preview" {
					op = "batch"
				}
				if req.Operation != "" && req.Operation != op {
					e = identity.Err(identity.Invalid, "operation mismatch")
				}
				req.Operation = op
			} else if parts[0] == "imports" && parts[1] != "preview" {
				e = identity.Err(identity.NotFound, "unknown import endpoint")
			}
			if e == nil {
				result, e = s.PreviewManagement(r.Context(), req)
			}
		}
	}
	if e != nil {
		writeError(w, e)
	} else {
		writeJSON(w, 200, result)
	}
	return true
}
