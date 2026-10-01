package api

import (
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"io"
	"net/http"
	"strings"
)

func snellRoute(w http.ResponseWriter, r *http.Request, q application.Queries) bool {
	if r.URL.Path != "/api/v1/inbounds" && !strings.HasPrefix(r.URL.Path, "/api/v1/inbounds/") && !strings.HasPrefix(r.URL.Path, "/api/v1/snell/") && !strings.HasPrefix(r.URL.Path, "/api/v1/hysteria2/") {
		return false
	}
	s, ok := q.(application.InboundCommands)
	if !ok {
		writeError(w, identity.Err(identity.NotImplemented, "runtime unavailable"))
		return true
	}
	if r.URL.RawQuery != "" {
		writeError(w, identity.Err(identity.Invalid, "query not accepted"))
		return true
	}
	var result any
	var err error
	method := http.MethodPost
	if r.URL.Path == "/api/v1/inbounds" || strings.HasPrefix(r.URL.Path, "/api/v1/inbounds/") && len(strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/inbounds/"), "/")) == 1 {
		method = http.MethodGet
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeJSON(w, 405, Problem{Code: identity.Invalid, Message: "method not allowed", RequestID: requestID()})
		return true
	}
	var body []byte
	if method == http.MethodPost {
		body, err = io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil || len(body) > 65536 {
			writeError(w, identity.Err(identity.Invalid, "request exceeds limit"))
			return true
		}
	}
	switch r.URL.Path {
	case "/api/v1/inbounds":
		result, err = s.Inbounds(r.Context())
	case "/api/v1/snell/validate":
		err = s.ValidateSnell(r.Context(), body)
		result = map[string]bool{"valid": true}
	case "/api/v1/snell/plan":
		result, err = s.PlanSnell(r.Context(), body)
	case "/api/v1/snell/apply":
		var req application.ApplyRequest
		err = application.StrictJSON(body, &req)
		if err == nil {
			result, err = s.ApplySnell(r.Context(), req)
		}
	case "/api/v1/hysteria2/validate", "/api/v1/hysteria2/plan", "/api/v1/hysteria2/apply":
		hy, ok := q.(application.Hysteria2Commands)
		if !ok {
			err = identity.Err(identity.NotImplemented, "Hysteria2 commands unavailable")
			break
		}
		switch r.URL.Path {
		case "/api/v1/hysteria2/validate":
			err = hy.ValidateHysteria2(r.Context(), body)
			result = map[string]bool{"valid": true}
		case "/api/v1/hysteria2/plan":
			result, err = hy.PlanHysteria2(r.Context(), body)
		case "/api/v1/hysteria2/apply":
			var req application.ApplyRequest
			err = application.StrictJSON(body, &req)
			if err == nil {
				result, err = hy.ApplyHysteria2(r.Context(), req)
			}
		}
	default:
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/inbounds/"), "/")
		id, e := identity.ParseID(parts[0])
		err = e
		if err == nil {
			switch {
			case len(parts) == 1:
				result, err = s.Inbound(r.Context(), id)
			case len(parts) == 2 && parts[1] == "export":
				var req application.ExportRequest
				err = application.StrictJSON(body, &req)
				if err == nil {
					result, err = s.ExportClient(r.Context(), id, req)
				}
			case len(parts) == 2 && parts[1] == "display":
				var req application.DisplayRequest
				err = application.StrictJSON(body, &req)
				if err == nil {
					result, err = s.SetDisplay(r.Context(), id, req)
				}
			case len(parts) == 2 && parts[1] == "binding":
				hy, ok := q.(application.Hysteria2Commands)
				if !ok {
					err = identity.Err(identity.NotImplemented, "binding mutation unavailable")
					break
				}
				var req application.BindingRequest
				err = application.StrictJSON(body, &req)
				if err == nil {
					result, err = hy.SetBinding(r.Context(), id, req)
				}
			default:
				err = identity.Err(identity.NotFound, "unknown endpoint")
			}
		}
	}
	if err != nil {
		writeError(w, err)
	} else {
		if page, ok := result.(application.InboundPage); ok {
			b, _ := json.Marshal(page.Revision)
			w.Header().Set("ETag", string(b))
		}
		if view, ok := result.(application.InboundView); ok {
			b, _ := json.Marshal(view.Inbound.Revision)
			w.Header().Set("ETag", string(b))
		}
		writeJSON(w, 200, result)
	}
	return true
}
