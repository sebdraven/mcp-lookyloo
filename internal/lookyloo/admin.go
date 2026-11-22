package lookyloo

import (
	"context"
	"encoding/json"
	"net/http"
)

func (c *Client) adminCapture(ctx context.Context, uuid, action string) (json.RawMessage, error) {
	path, err := capturePath("/admin/", uuid, "/"+action)
	if err != nil {
		return nil, err
	}
	return c.doJSON(ctx, request{method: http.MethodPost, path: path, auth: authRequired, bulk: true})
}

func (c *Client) AdminHide(ctx context.Context, uuid string) (json.RawMessage, error) {
	return c.adminCapture(ctx, uuid, "hide")
}

func (c *Client) AdminRebuild(ctx context.Context, uuid string) (json.RawMessage, error) {
	return c.adminCapture(ctx, uuid, "rebuild")
}

func (c *Client) AdminRemove(ctx context.Context, uuid string) (json.RawMessage, error) {
	return c.adminCapture(ctx, uuid, "remove")
}

func (c *Client) AdminRebuildAllCache(ctx context.Context) (json.RawMessage, error) {
	return c.doJSON(ctx, request{method: http.MethodPost, path: "/admin/rebuild_all_cache", auth: authRequired, bulk: true})
}

func (c *Client) AdminRebuildAll(ctx context.Context) (json.RawMessage, error) {
	return c.doJSON(ctx, request{method: http.MethodPost, path: "/admin/rebuild_all", auth: authRequired, bulk: true})
}
