// Package mcptools exposes the Lookyloo client over MCP.
package mcptools

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
)

const (
	defaultPageSize = 100
	maxPageSize     = 10000
)

type Options struct {
	OutDir string
}

type registry struct {
	client *lookyloo.Client
	names  []string
}

// Register adds the tools to s and returns their names in registration order.
func Register(s *mcp.Server, c *lookyloo.Client, _ Options) []string {
	r := &registry{client: c}
	r.captureTools(s)
	r.instanceTools(s)
	return r.names
}

func addTool[In, Out any](r *registry, s *mcp.Server, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	mcp.AddTool(s, t, h)
	r.names = append(r.names, t.Name)
}

func readOnly() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)}
}

func rawResult(raw json.RawMessage) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}}
}

func captureErr(err error) error {
	var ae *lookyloo.APIError
	if errors.As(err, &ae) {
		switch ae.StatusCode {
		case http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError:
			return fmt.Errorf("%w — Lookyloo answers this for an unknown capture or one still being processed; check lk_capture_status", err)
		}
	}
	return err
}

type page struct {
	Total      int  `json:"total"`
	Offset     int  `json:"offset"`
	Count      int  `json:"count"`
	HasMore    bool `json:"has_more"`
	NextOffset int  `json:"next_offset,omitempty"`
}

func checkPage(limit, offset int) (int, error) {
	if limit < 0 || limit > maxPageSize {
		return 0, fmt.Errorf("limit must be between 1 and %d (0 means %d)", maxPageSize, defaultPageSize)
	}
	if offset < 0 {
		return 0, errors.New("offset must not be negative")
	}
	if limit == 0 {
		limit = defaultPageSize
	}
	return limit, nil
}

func paginate(all []string, limit, offset int) ([]string, page) {
	p := page{Total: len(all), Offset: offset}
	items := []string{}
	if offset < len(all) {
		end := min(offset+limit, len(all))
		items = append(items, all[offset:end]...)
		if end < len(all) {
			p.HasMore = true
			p.NextOffset = end
		}
	}
	p.Count = len(items)
	return items, p
}
