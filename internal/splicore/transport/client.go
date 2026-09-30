// Package transport provides local control transports independent of HTTP semantics.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

var ErrNotRunning = errors.New("splicore is not running")

type Client struct {
	http   *http.Client
	origin string
}

func UnixClient(path string) *Client {
	t := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
	}}
	return &Client{http: &http.Client{Transport: t, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, origin: "http://localhost"}
}

// TestClient is only for explicitly owned httptest transports; no production TCP listener.
func TestClient(client *http.Client, origin string) *Client {
	return &Client{http: client, origin: origin}
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
	if err != nil {
		return identity.Err(identity.Invalid, "invalid control request")
	}
	response, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return identity.Err(identity.Unavailable, "control request timed out or canceled")
		}
		if daemonAbsent(err) {
			return ErrNotRunning
		}
		return identity.Err(identity.Unavailable, "control transport unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return identity.Err(identity.Unavailable, "control service rejected request")
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return identity.Err(identity.Unavailable, "invalid control response type")
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return identity.Err(identity.Unavailable, "control response exceeds limit")
	}
	if json.Unmarshal(b, out) != nil {
		return identity.Err(identity.Unavailable, "invalid control response")
	}
	return nil
}

func (c *Client) System(ctx context.Context) (application.System, error) {
	var out application.System
	err := c.get(ctx, "/api/v1/system", &out)
	return out, err
}

func (c *Client) Capabilities(ctx context.Context, cursor string, limit int) (application.CapabilityPage, error) {
	var out application.CapabilityPage
	err := c.get(ctx, capabilityPath(cursor, limit), &out)
	return out, err
}
