package transport

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

func (c *Client) managementPost(ctx context.Context, path string, r, out any) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return c.post(ctx, path, b, out)
}
func (c *Client) PreviewManagement(ctx context.Context, r application.ManagementRequest) (application.ManagementPreview, error) {
	var out application.ManagementPreview
	e := c.managementPost(ctx, "/api/v1/imports/preview", r, &out)
	return out, e
}
func (c *Client) ApplyManagement(ctx context.Context, r application.ManagementApply) (application.ClientResult, error) {
	var out application.ClientResult
	e := c.managementPost(ctx, "/api/v1/imports/apply", r, &out)
	return out, e
}
func (c *Client) PreviewProviderRefresh(ctx context.Context, id identity.ID) (application.ManagementPreview, error) {
	var out application.ManagementPreview
	if id.Validate() != nil {
		return out, identity.Err(identity.Invalid, "invalid provider ID")
	}
	collection, e := c.providerCollection(ctx, id)
	if e == nil {
		e = c.managementPost(ctx, "/api/v1/"+collection+"/"+string(id)+"/refresh-preview", struct{}{}, &out)
	}
	return out, e
}
func (c *Client) RefreshProvider(ctx context.Context, id identity.ID) (application.ClientResult, error) {
	var out application.ClientResult
	if id.Validate() != nil {
		return out, identity.Err(identity.Invalid, "invalid provider ID")
	}
	collection, e := c.providerCollection(ctx, id)
	if e == nil {
		e = c.managementPost(ctx, "/api/v1/"+collection+"/"+string(id)+"/refresh", struct{}{}, &out)
	}
	return out, e
}
func (c *Client) providerCollection(ctx context.Context, id identity.ID) (string, error) {
	status, err := c.ClientStatus(ctx)
	if err != nil {
		return "", err
	}
	for _, p := range status.State.Management.Providers {
		if p.ID == id {
			if p.Kind == "ruleset" {
				return "rule-set-providers", nil
			}
			return "providers", nil
		}
	}
	return "", identity.Err(identity.NotFound, "provider not found")
}
func (c *Client) ExportNodes(ctx context.Context, r application.NodeExportRequest) (application.NodeExport, error) {
	var out application.NodeExport
	e := c.managementPost(ctx, "/api/v1/nodes/export", r, &out)
	return out, e
}
