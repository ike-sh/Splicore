package transport

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func (c *Client) ValidateHysteria2(ctx context.Context, b json.RawMessage) error {
	var v any
	return c.post(ctx, "/api/v1/hysteria2/validate", b, &v)
}
func (c *Client) PlanHysteria2(ctx context.Context, b json.RawMessage) (application.Hysteria2Plan, error) {
	var v application.Hysteria2Plan
	e := c.post(ctx, "/api/v1/hysteria2/plan", b, &v)
	return v, e
}
func (c *Client) ApplyHysteria2(ctx context.Context, r application.ApplyRequest) (application.Hysteria2ApplyResult, error) {
	var v application.Hysteria2ApplyResult
	b, e := json.Marshal(r)
	if e == nil {
		e = c.post(ctx, "/api/v1/hysteria2/apply", b, &v)
	}
	return v, e
}
func (c *Client) SetBinding(ctx context.Context, id identity.ID, r application.BindingRequest) (identity.Transaction, error) {
	var v identity.Transaction
	if e := id.Validate(); e != nil {
		return v, e
	}
	b, e := json.Marshal(r)
	if e == nil {
		e = c.post(ctx, "/api/v1/inbounds/"+string(id)+"/binding", b, &v)
	}
	return v, e
}
