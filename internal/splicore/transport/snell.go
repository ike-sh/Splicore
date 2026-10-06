package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"io"
	"net/http"
)

func (c *Client) post(ctx context.Context, path string, b []byte, out any) error {
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+path, bytes.NewReader(b))
	if e != nil {
		return identity.Err(identity.Invalid, "invalid control request")
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return identity.Err(identity.Unavailable, "control transport unavailable")
	}
	defer res.Body.Close()
	data, e := io.ReadAll(io.LimitReader(res.Body, 4<<20+1))
	if e != nil || len(data) > 4<<20 {
		return identity.Err(identity.Unavailable, "invalid control response")
	}
	if res.StatusCode != 200 {
		var p struct {
			Code    identity.Code      `json:"code"`
			Current *identity.Revision `json:"current_revision"`
		}
		if json.Unmarshal(data, &p) == nil {
			if p.Code == identity.Conflict && p.Current != nil {
				return identity.RevisionConflict(*p.Current)
			}
			switch p.Code {
			case identity.Invalid, identity.NotFound, identity.NotImplemented, identity.UnsupportedExport, identity.PortConflict, identity.UnsupportedEngineForProtocol:
				return identity.Err(p.Code, "control command rejected")
			}
		}
		return identity.Err(identity.Unavailable, "control command failed")
	}
	if res.Header.Get("Content-Type") != "application/json" || json.Unmarshal(data, out) != nil {
		return identity.Err(identity.Unavailable, "invalid control response")
	}
	return nil
}
func (c *Client) Inbounds(ctx context.Context) (application.InboundPage, error) {
	var v application.InboundPage
	e := c.get(ctx, "/api/v1/inbounds", &v)
	return v, e
}
func (c *Client) Inbound(ctx context.Context, id identity.ID) (application.InboundView, error) {
	var v application.InboundView
	if e := id.Validate(); e != nil {
		return v, e
	}
	e := c.get(ctx, "/api/v1/inbounds/"+string(id), &v)
	return v, e
}
func (c *Client) ValidateSnell(ctx context.Context, b json.RawMessage) error {
	var v any
	return c.post(ctx, "/api/v1/snell/validate", b, &v)
}
func (c *Client) PlanSnell(ctx context.Context, b json.RawMessage) (application.Plan, error) {
	var v application.Plan
	e := c.post(ctx, "/api/v1/snell/plan", b, &v)
	return v, e
}
func (c *Client) ApplySnell(ctx context.Context, r application.ApplyRequest) (application.ApplyResult, error) {
	var v application.ApplyResult
	b, e := json.Marshal(r)
	if e == nil {
		e = c.post(ctx, "/api/v1/snell/apply", b, &v)
	}
	return v, e
}
func (c *Client) ExportSnell(ctx context.Context, id identity.ID, r application.ExportRequest) (application.ExportResult, error) {
	return c.ExportClient(ctx, id, r)
}
func (c *Client) ExportClient(ctx context.Context, id identity.ID, r application.ExportRequest) (application.ExportResult, error) {
	var v application.ExportResult
	if e := id.Validate(); e != nil {
		return v, e
	}
	b, e := json.Marshal(r)
	if e == nil {
		e = c.post(ctx, "/api/v1/inbounds/"+string(id)+"/export", b, &v)
	}
	return v, e
}
func (c *Client) SetDisplay(ctx context.Context, id identity.ID, r application.DisplayRequest) (identity.Transaction, error) {
	var v identity.Transaction
	if e := id.Validate(); e != nil {
		return v, e
	}
	b, e := json.Marshal(r)
	if e == nil {
		e = c.post(ctx, "/api/v1/inbounds/"+string(id)+"/display", b, &v)
	}
	return v, e
}
