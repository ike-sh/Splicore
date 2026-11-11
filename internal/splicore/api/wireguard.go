package api

import (
	"io"
	"net/http"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func wireGuardRoute(w http.ResponseWriter, r *http.Request, q application.Queries) bool {
	const prefix = "/api/v1/wireguard/endpoints"
	if r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
		return false
	}
	fail := func(err error) bool { writeError(w, err); return true }
	service, ok := q.(application.WireGuardCommands)
	if !ok {
		return fail(identity.Err(identity.NotImplemented, "WireGuard service unavailable"))
	}
	if r.URL.RawQuery != "" {
		return fail(identity.Err(identity.Invalid, "WireGuard query parameters not accepted"))
	}
	tail := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.TrimPrefix(tail, "/"), "/")
	allowed := ""
	tag := ""
	op := ""
	if tail == "" {
		allowed = "GET, POST"
	} else if len(parts) == 1 && parts[0] == "validate" {
		allowed = "POST"
		op = "validate"
	} else if len(parts) == 1 && parts[0] != "" {
		allowed = "GET"
		tag = parts[0]
	} else if len(parts) == 2 && parts[0] != "" && (parts[1] == "start" || parts[1] == "close" || parts[1] == "replace") {
		allowed = "POST"
		tag = parts[0]
		op = parts[1]
	}
	if allowed == "" {
		return fail(identity.Err(identity.NotFound, "unknown WireGuard endpoint"))
	}
	if !strings.Contains(", "+allowed+", ", ", "+r.Method+", ") {
		w.Header().Set("Allow", allowed)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	var result any
	var err error
	if r.Method == http.MethodGet {
		if tag == "" {
			result, err = service.WireGuardEndpoints(r.Context())
		} else {
			result, err = service.WireGuardEndpointStatus(r.Context(), tag)
		}
	} else {
		body, e := io.ReadAll(io.LimitReader(r.Body, application.ClientDocumentLimit+1))
		if e != nil || len(body) > application.ClientDocumentLimit {
			return fail(identity.Err(identity.Invalid, "WireGuard request exceeds limit"))
		}
		if op == "start" || op == "close" {
			var empty struct{}
			if len(body) > 0 {
				err = application.StrictClientJSON(body, &empty)
			}
			if err == nil {
				if op == "start" {
					result, err = service.StartWireGuardEndpoint(r.Context(), tag)
				} else {
					result, err = service.CloseWireGuardEndpoint(r.Context(), tag)
				}
			}
		} else {
			var config E.WireGuard
			err = application.StrictClientJSON(body, &config)
			if err == nil {
				if op == "replace" && config.Tag != tag {
					return fail(identity.Err(identity.Invalid, "WireGuard replacement tag mismatch"))
				}
				switch op {
				case "replace":
					result, err = service.ReplaceWireGuardEndpoint(r.Context(), config)
				case "validate":
					err = service.ValidateWireGuardEndpoint(r.Context(), config)
					result = map[string]bool{"valid": err == nil}
				default:
					result, err = service.CreateWireGuardEndpoint(r.Context(), config)
				}
			}
		}
	}
	if err != nil {
		return fail(err)
	}
	writeJSON(w, http.StatusOK, result)
	return true
}
