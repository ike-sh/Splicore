package transport

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/networkruntime"
)

func (c *Client) RouteExplain(ctx context.Context, q networkruntime.Query) (networkruntime.Explanation, error) {
	var v networkruntime.Explanation
	b, err := json.Marshal(q)
	if err == nil {
		err = c.post(ctx, "/api/v1/routes/explain", b, &v)
	}
	return v, err
}
func (c *Client) DNSLookup(ctx context.Context, domain string) (networkruntime.DNSResult, error) {
	var v networkruntime.DNSResult
	b, _ := json.Marshal(map[string]string{"domain": domain})
	err := c.post(ctx, "/api/v1/dns/lookup", b, &v)
	return v, err
}
func (c *Client) FlushDNS(ctx context.Context) error {
	var v any
	return c.post(ctx, "/api/v1/dns/cache/flush", []byte(`{}`), &v)
}
