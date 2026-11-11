package transport

import (
	"context"
	"encoding/json"
	"net/url"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/wireguardendpoint"
)

const wireGuardPath = "/api/v1/wireguard/endpoints"

// wireGuardInput is an explicit sensitive request boundary, not a status or
// diagnostic serialization. Ordinary typed configuration remains redacted.
func wireGuardInput(c E.WireGuard) (json.RawMessage, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(b, &fields); err != nil {
		return nil, err
	}
	fields["private_key"], err = json.Marshal(E.EncodeKey(c.PrivateKey.Reveal()))
	if err != nil {
		return nil, err
	}
	peers := make([]map[string]json.RawMessage, len(c.Peers))
	for i, p := range c.Peers {
		raw, _ := json.Marshal(p)
		_ = json.Unmarshal(raw, &peers[i])
		delete(peers[i], "pre_shared_key")
		if p.PreSharedKey.Present() {
			peers[i]["pre_shared_key"], _ = json.Marshal(E.EncodeKey(p.PreSharedKey.Reveal()))
		}
	}
	fields["peers"], err = json.Marshal(peers)
	if err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

func (c *Client) ValidateWireGuardEndpoint(ctx context.Context, config E.WireGuard) error {
	b, err := wireGuardInput(config)
	if err != nil {
		return err
	}
	var out any
	return c.post(ctx, wireGuardPath+"/validate", b, &out)
}

func (c *Client) CreateWireGuardEndpoint(ctx context.Context, config E.WireGuard) (wireguardendpoint.Status, error) {
	var out wireguardendpoint.Status
	b, err := wireGuardInput(config)
	if err == nil {
		err = c.post(ctx, wireGuardPath, b, &out)
	}
	return out, err
}

func (c *Client) StartWireGuardEndpoint(ctx context.Context, tag string) (wireguardendpoint.Status, error) {
	var out wireguardendpoint.Status
	err := c.post(ctx, wireGuardPath+"/"+url.PathEscape(tag)+"/start", json.RawMessage(`{}`), &out)
	return out, err
}

func (c *Client) CloseWireGuardEndpoint(ctx context.Context, tag string) (wireguardendpoint.Status, error) {
	var out wireguardendpoint.Status
	err := c.post(ctx, wireGuardPath+"/"+url.PathEscape(tag)+"/close", json.RawMessage(`{}`), &out)
	return out, err
}

func (c *Client) WireGuardEndpointStatus(ctx context.Context, tag string) (wireguardendpoint.Status, error) {
	var out wireguardendpoint.Status
	err := c.get(ctx, wireGuardPath+"/"+url.PathEscape(tag), &out)
	return out, err
}

func (c *Client) WireGuardEndpoints(ctx context.Context) ([]wireguardendpoint.Status, error) {
	var out []wireguardendpoint.Status
	err := c.get(ctx, wireGuardPath, &out)
	return out, err
}

func (c *Client) ReplaceWireGuardEndpoint(ctx context.Context, config E.WireGuard) (wireguardendpoint.Status, error) {
	var out wireguardendpoint.Status
	b, err := wireGuardInput(config)
	if err == nil {
		err = c.post(ctx, wireGuardPath+"/"+url.PathEscape(config.Tag)+"/replace", b, &out)
	}
	return out, err
}
