package mcptools

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (r *registry) adminCaptureTool(s *mcp.Server, name, description string, act func(context.Context, string) (json.RawMessage, error)) {
	addTool(r, s, &mcp.Tool{Name: name, Description: description},
		func(ctx context.Context, _ *mcp.CallToolRequest, in captureInput) (*mcp.CallToolResult, any, error) {
			raw, err := act(ctx, in.CaptureUUID)
			if err != nil {
				return nil, nil, err
			}
			return rawResult(raw), nil, nil
		})
}

func (r *registry) adminTools(s *mcp.Server) {
	c := r.client
	const gate = " Administration: needs an API token, only registered with -allow-admin."

	r.adminCaptureTool(s, "lk_admin_hide",
		"Hide a capture from the index of the instance (reversible on the instance)."+gate, c.AdminHide)
	r.adminCaptureTool(s, "lk_admin_rebuild",
		"Rebuild the tree of a capture from its stored files."+gate, c.AdminRebuild)
	r.adminCaptureTool(s, "lk_admin_remove",
		"REMOVE a capture from the instance. Destructive and irreversible."+gate, c.AdminRemove)
	r.rawInstanceTool(s, "lk_admin_rebuild_cache",
		"Rebuild every cache of the instance. Takes a while."+gate, c.AdminRebuildAllCache)
	r.rawInstanceTool(s, "lk_admin_rebuild_all",
		"Rebuild every capture tree of the instance. Lookyloo warns it takes a VERY long time; the call may time out while the rebuild goes on."+gate, c.AdminRebuildAll)
}
