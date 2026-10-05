package transport

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/clientruntime"
	"github.com/sagernet/sing-box/internal/splicore/ports"
)

func (c *Client) ClientStatus(ctx context.Context) (clientruntime.Status, error) {
	var v clientruntime.Status
	err := c.get(ctx, "/api/v1/client/runtime", &v)
	return v, err
}
func (c *Client) ValidateClient(ctx context.Context, b json.RawMessage) error {
	var v any
	return c.post(ctx, "/api/v1/client/validate", b, &v)
}
func (c *Client) PlanClient(ctx context.Context, b json.RawMessage) (ports.ClientPlan, error) {
	var v ports.ClientPlan
	err := c.post(ctx, "/api/v1/client/plan", b, &v)
	return v, err
}
func (c *Client) ApplyClient(ctx context.Context, r application.ApplyRequest) (application.ClientResult, error) {
	var v application.ClientResult
	b, err := json.Marshal(r)
	if err == nil {
		err = c.post(ctx, "/api/v1/client/apply", b, &v)
	}
	return v, err
}
