// Package api implements API v1 semantics independently of socket transport.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

type Problem struct {
	Code            identity.Code      `json:"code"`
	Message         string             `json:"message"`
	RequestID       string             `json:"request_id"`
	CurrentRevision *identity.Revision `json:"current_revision,omitempty"`
}

func Handler(service application.Queries) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if snellRoute(w, r, service) {
			return
		}
		if r.URL.Path != "/api/v1/system" && r.URL.Path != "/api/v1/capabilities" {
			writeError(w, identity.Err(identity.NotFound, "unknown endpoint"))
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSON(w, http.StatusMethodNotAllowed, Problem{Code: identity.Invalid, Message: "method not allowed", RequestID: requestID()})
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			writeError(w, identity.Err(identity.Invalid, "invalid query"))
			return
		}
		for key, values := range query {
			if len(values) != 1 || (r.URL.Path == "/api/v1/system" || key != "cursor" && key != "limit") {
				writeError(w, identity.Err(identity.Invalid, "unknown or duplicate query parameter"))
				return
			}
		}
		if r.URL.Path == "/api/v1/system" {
			result, err := service.System(r.Context())
			if err != nil {
				writeError(w, err)
				return
			}
			w.Header().Set("ETag", `"`+strconv.FormatInt(int64(result.CommittedRevision), 10)+`"`)
			writeJSON(w, http.StatusOK, result)
			return
		}
		limit := 50
		if raw, ok := query["limit"]; ok {
			limit, err = strconv.Atoi(raw[0])
			if err != nil || limit < 1 || limit > 200 {
				writeError(w, identity.Err(identity.Invalid, "invalid page limit"))
				return
			}
		}
		result, err := service.Capabilities(r.Context(), query.Get("cursor"), limit)
		if err != nil {
			writeError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(int64(result.SnapshotRevision), 10)+`"`)
		writeJSON(w, http.StatusOK, result)
	})
}

func requestID() string {
	id, err := identity.NewID()
	if err != nil {
		return "unavailable"
	}
	return string(id)
}

func writeError(w http.ResponseWriter, err error) {
	code, message, status := identity.Unavailable, "service unavailable", http.StatusServiceUnavailable
	var current *identity.Revision
	var de *identity.Error
	if errors.As(err, &de) {
		code = de.Code
		switch de.Code {
		case identity.Invalid:
			status = http.StatusBadRequest
			message = "invalid request"
		case identity.NotFound:
			status = http.StatusNotFound
			message = "resource not found"
		case identity.Conflict:
			status = http.StatusConflict
			message = "revision conflict"
			r := de.Current
			current = &r
		case identity.NotImplemented:
			status = http.StatusNotImplemented
			message = "operation not implemented"
		case identity.UnsupportedExport:
			status = http.StatusUnprocessableEntity
			message = "unsupported client export"
		case identity.UnsupportedEngineForProtocol:
			status = http.StatusUnprocessableEntity
			message = "unsupported engine for protocol"
		case identity.UnsupportedPolicyForEngine:
			status = http.StatusUnprocessableEntity
			message = "unsupported policy for engine"
		case identity.PortConflict:
			status = http.StatusConflict
			message = "listener port is already in use"
		}
	}
	writeJSON(w, status, Problem{Code: code, Message: message, RequestID: requestID(), CurrentRevision: current})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "response unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
