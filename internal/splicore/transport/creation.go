package transport

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func creationPath(protocol, action string) (string, error) {
	if !identity.Label(protocol, 64) {
		return "", identity.Err(identity.Invalid, "invalid protocol")
	}
	for _, c := range protocol {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return "", identity.Err(identity.Invalid, "invalid protocol")
		}
	}
	return "/api/v1/creation/" + protocol + "/" + action, nil
}
func (c *Client) ValidateCreation(ctx context.Context, protocol string, b json.RawMessage) error {
	path, err := creationPath(protocol, "validate")
	if err != nil {
		return err
	}
	var v any
	return c.post(ctx, path, b, &v)
}
func (c *Client) PlanCreation(ctx context.Context, protocol string, b json.RawMessage) (application.CreationPlan, error) {
	var v application.CreationPlan
	path, err := creationPath(protocol, "plan")
	if err == nil {
		err = c.post(ctx, path, b, &v)
	}
	return v, err
}
func (c *Client) ApplyCreation(ctx context.Context, protocol string, r application.ApplyRequest) (application.CreationResult, error) {
	var v application.CreationResult
	path, err := creationPath(protocol, "apply")
	if err != nil {
		return v, err
	}
	b, err := json.Marshal(r)
	if err == nil {
		err = c.post(ctx, path, b, &v)
	}
	return v, err
}
