package lookyloo

import (
	"context"
	"encoding/json"
	"net/http"
)

func (c *Client) Devices(ctx context.Context) (json.RawMessage, error) {
	return c.doJSON(ctx, request{method: http.MethodGet, path: "/json/devices", auth: authOptional})
}

func (c *Client) InstanceStats(ctx context.Context) (json.RawMessage, error) {
	return c.doJSON(ctx, request{method: http.MethodGet, path: "/json/stats", auth: authOptional})
}

func (c *Client) UserConfig(ctx context.Context) (json.RawMessage, error) {
	return c.doJSON(ctx, request{method: http.MethodGet, path: "/json/get_user_config", auth: authRequired})
}
