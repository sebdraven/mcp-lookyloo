package mcptools

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (r *registry) rawInstanceTool(s *mcp.Server, name, description string, fetch func(context.Context) (json.RawMessage, error)) {
	addTool(r, s, &mcp.Tool{Name: name, Description: description},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			raw, err := fetch(ctx)
			if err != nil {
				return nil, nil, err
			}
			return rawResult(raw), nil, nil
		})
}

func (r *registry) instanceTools(s *mcp.Server) {
	c := r.client

	r.rawInstanceTool(s, "lk_devices",
		"The devices preconfigured on the instance, by category; their names are the valid device_name values for lk_submit.", c.Devices)

	r.rawInstanceTool(s, "lk_instance_stats",
		"Submission, redirect, URL and domain counts of the instance, per week and per month.", c.InstanceStats)

	r.rawInstanceTool(s, "lk_user_config",
		"The configuration of the authenticated user, or null when the user has none. Needs an API token.", c.UserConfig)
}
