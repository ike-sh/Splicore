package transport

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/ike-sh/Splicore/internal/splicore/amneziawgendpoint"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
)

const amneziaWGPath = "/api/v1/amneziawg/endpoints"

// amneziaWGInput is an explicit sensitive request boundary, not a status or
// diagnostic serialization. Ordinary typed configuration remains redacted.
func amneziaWGInput(c E.AmneziaWG) (json.RawMessage, error) {
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
	delete(fields, "header_protection_key")
	if c.HeaderProtectionKey.Present() {
		fields["header_protection_key"], _ = json.Marshal(E.EncodeKey(c.HeaderProtectionKey.Reveal()))
	}
	fields["peers"], err = json.Marshal(peers)
	if err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

func (c *Client) ValidateAmneziaWGEndpoint(ctx context.Context, config E.AmneziaWG) error {
	b, err := amneziaWGInput(config)
	if err != nil {
		return err
	}
	var out any
	return c.post(ctx, amneziaWGPath+"/validate", b, &out)
}

func (c *Client) CreateAmneziaWGEndpoint(ctx context.Context, config E.AmneziaWG) (amneziawgendpoint.Status, error) {
	var out amneziawgendpoint.Status
	b, err := amneziaWGInput(config)
	if err == nil {
		err = c.post(ctx, amneziaWGPath, b, &out)
	}
	return out, err
}

func (c *Client) StartAmneziaWGEndpoint(ctx context.Context, tag string) (amneziawgendpoint.Status, error) {
	var out amneziawgendpoint.Status
	err := c.post(ctx, amneziaWGPath+"/"+url.PathEscape(tag)+"/start", json.RawMessage(`{}`), &out)
	return out, err
}

func (c *Client) CloseAmneziaWGEndpoint(ctx context.Context, tag string) (amneziawgendpoint.Status, error) {
	var out amneziawgendpoint.Status
	err := c.post(ctx, amneziaWGPath+"/"+url.PathEscape(tag)+"/close", json.RawMessage(`{}`), &out)
	return out, err
}

func (c *Client) AmneziaWGEndpointStatus(ctx context.Context, tag string) (amneziawgendpoint.Status, error) {
	var out amneziawgendpoint.Status
	err := c.get(ctx, amneziaWGPath+"/"+url.PathEscape(tag), &out)
	return out, err
}

func (c *Client) AmneziaWGEndpoints(ctx context.Context) ([]amneziawgendpoint.Status, error) {
	var out []amneziawgendpoint.Status
	err := c.get(ctx, amneziaWGPath, &out)
	return out, err
}

func (c *Client) ReplaceAmneziaWGEndpoint(ctx context.Context, config E.AmneziaWG) (amneziawgendpoint.Status, error) {
	var out amneziawgendpoint.Status
	b, err := amneziaWGInput(config)
	if err == nil {
		err = c.post(ctx, amneziaWGPath+"/"+url.PathEscape(config.Tag)+"/replace", b, &out)
	}
	return out, err
}
