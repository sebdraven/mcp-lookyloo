package mcptools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
)

const defaultOccurrences = 20

type urlInfoInput struct {
	URL                string `json:"url" jsonschema:"the exact URL to look for in the indexed captures"`
	Limit              int    `json:"limit,omitempty" jsonschema:"maximum number of captures to return (default 20)"`
	CachedCapturesOnly *bool  `json:"cached_captures_only,omitempty" jsonschema:"true (default) searches only the captures in cache; false re-caches the missing ones, which can take minutes"`
}

type hostnameInfoInput struct {
	Hostname           string `json:"hostname" jsonschema:"the hostname to look for in the indexed captures"`
	Limit              int    `json:"limit,omitempty" jsonschema:"maximum number of captures to return (default 20)"`
	CachedCapturesOnly *bool  `json:"cached_captures_only,omitempty" jsonschema:"true (default) searches only the captures in cache; false re-caches the missing ones, which can take minutes"`
}

type occurrencesOutput struct {
	Count     int              `json:"count"`
	Truncated bool             `json:"truncated"`
	Captures  []map[string]any `json:"captures"`
}

type hashInfoInput struct {
	H string `json:"h" jsonschema:"complete SHA512 of a resource body, 128 hexadecimal characters"`
}

type tldInput struct {
	TLD               string `json:"tld,omitempty" jsonschema:"TLD to look for, e.g. com or co.uk; without it the tool lists the TLDs seen recently"`
	OldestCapture     string `json:"oldest_capture,omitempty" jsonschema:"Unix timestamp of the oldest capture to consider (Lookyloo default: 5 days ago)"`
	MostRecentCapture string `json:"most_recent_capture,omitempty" jsonschema:"Unix timestamp of the most recent capture to consider (default: now)"`
	URLsOnly          bool   `json:"urls_only,omitempty" jsonschema:"return the URLs with that TLD instead of the captures; slow on a frequent TLD"`
}

type categoriesInput struct {
	Category string `json:"category,omitempty" jsonschema:"category name; without it the tool returns every category with its captures"`
}

type recentInput struct {
	Timestamp string `json:"timestamp,omitempty" jsonschema:"Unix timestamp; only captures done since then are returned (default: all)"`
	Limit     int    `json:"limit,omitempty" jsonschema:"UUIDs per page, 1 to 10000 (default 100)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"index of the first UUID, from next_offset of the previous page (default 0)"`
}

type recentOutput struct {
	Captures []string `json:"captures"`
	page
}

type compareInput struct {
	CaptureLeft             string   `json:"capture_left" jsonschema:"UUID of the first capture"`
	CaptureRight            string   `json:"capture_right" jsonschema:"UUID of the second capture"`
	RessourcesIgnoreDomains []string `json:"ressources_ignore_domains,omitempty" jsonschema:"domains whose resources are left out of the comparison"`
	RessourcesIgnoreRegexes []string `json:"ressources_ignore_regexes,omitempty" jsonschema:"regular expressions; resources whose URL matches one are left out"`
}

type takedownInput struct {
	CaptureUUID string `json:"capture_uuid" jsonschema:"UUID of the capture"`
	Filter      bool   `json:"filter,omitempty" jsonschema:"true returns only the abuse email addresses"`
}

func (r *registry) searchTools(s *mcp.Server) {
	addTool(r, s, &mcp.Tool{
		Name: "lk_url_info",
		Description: "Find the captures in which an exact URL was loaded, most recent first, with the URL nodes and the SHA512 of their bodies. " +
			"Without an API token only public captures are searched.",
		Annotations: readOnly(),
	}, r.urlInfo)

	addTool(r, s, &mcp.Tool{
		Name: "lk_hostname_info",
		Description: "Find the captures in which a hostname was contacted, most recent first, with the matching host nodes. " +
			"Without an API token only public captures are searched.",
		Annotations: readOnly(),
	}, r.hostnameInfo)

	addTool(r, s, &mcp.Tool{
		Name: "lk_hash_info",
		Description: "Look up a resource body by its complete SHA512: the captures and URL nodes that loaded it, and the body itself, base64-encoded." +
			hostile,
		Annotations: readOnly(),
	}, r.hashInfo)

	addTool(r, s, &mcp.Tool{
		Name: "lk_tld_captures",
		Description: "Without tld: the TLDs seen in recent captures. With tld: the [capture UUID, Unix timestamp] pairs of the captures that hit it, " +
			"or with urls_only the URLs under it.",
		Annotations: readOnly(),
	}, r.tldCaptures)

	addTool(r, s, &mcp.Tool{
		Name:        "lk_categories",
		Description: "Without category: every category of the instance with the UUIDs of its captures. With category: the UUIDs in that category.",
		Annotations: readOnly(),
	}, r.categories)

	addTool(r, s, &mcp.Tool{
		Name: "lk_recent_captures",
		Description: "UUIDs of the captures of the instance, most recent first, one page at a time (limit, offset). " +
			"timestamp keeps only the captures done since that Unix time.",
		Annotations: readOnly(),
	}, r.recentCaptures)

	addTool(r, s, &mcp.Tool{
		Name: "lk_compare_captures",
		Description: "Compare two captures: root and final URL, final status code, redirect chain with IPs, resources in one, the other or both. " +
			"different is false when nothing differs.",
		Annotations: readOnly(),
	}, r.compareCaptures)

	addTool(r, s, &mcp.Tool{
		Name: "lk_takedown_info",
		Description: "Contacts for a takedown request about a capture (whois and abuse addresses of the hostnames and IPs it involved). " +
			"Needs UWhois on the instance; nothing is sent to anyone.",
		Annotations: readOnly(),
	}, r.takedownInfo)
}

func occurrenceLimit(limit int) (int, error) {
	if limit < 0 || limit > maxPageSize {
		return 0, fmt.Errorf("limit must be between 1 and %d (0 means %d)", maxPageSize, defaultOccurrences)
	}
	if limit == 0 {
		return defaultOccurrences, nil
	}
	return limit, nil
}

func occurrences(found []map[string]any, limit int) occurrencesOutput {
	out := occurrencesOutput{Captures: found}
	if len(found) > limit {
		out.Captures = found[:limit]
		out.Truncated = true
	}
	if out.Captures == nil {
		out.Captures = []map[string]any{}
	}
	out.Count = len(out.Captures)
	return out
}

func (r *registry) urlInfo(ctx context.Context, _ *mcp.CallToolRequest, in urlInfoInput) (*mcp.CallToolResult, occurrencesOutput, error) {
	limit, err := occurrenceLimit(in.Limit)
	if err != nil {
		return nil, occurrencesOutput{}, err
	}
	found, err := r.client.URLInfo(ctx, in.URL, limit, in.CachedCapturesOnly == nil || *in.CachedCapturesOnly)
	if err != nil {
		return nil, occurrencesOutput{}, err
	}
	return nil, occurrences(found, limit), nil
}

func (r *registry) hostnameInfo(ctx context.Context, _ *mcp.CallToolRequest, in hostnameInfoInput) (*mcp.CallToolResult, occurrencesOutput, error) {
	limit, err := occurrenceLimit(in.Limit)
	if err != nil {
		return nil, occurrencesOutput{}, err
	}
	found, err := r.client.HostnameInfo(ctx, in.Hostname, limit, in.CachedCapturesOnly == nil || *in.CachedCapturesOnly)
	if err != nil {
		return nil, occurrencesOutput{}, err
	}
	return nil, occurrences(found, limit), nil
}

func (r *registry) hashInfo(ctx context.Context, _ *mcp.CallToolRequest, in hashInfoInput) (*mcp.CallToolResult, any, error) {
	raw, err := r.client.HashInfo(ctx, in.H)
	if err != nil {
		return nil, nil, err
	}
	return rawResult(raw), nil, nil
}

func (r *registry) tldCaptures(ctx context.Context, _ *mcp.CallToolRequest, in tldInput) (*mcp.CallToolResult, any, error) {
	raw, err := r.client.TLDCaptures(ctx, lookyloo.TLDQuery{
		TLD:               in.TLD,
		OldestCapture:     in.OldestCapture,
		MostRecentCapture: in.MostRecentCapture,
		URLsOnly:          in.URLsOnly,
	})
	if err != nil {
		return nil, nil, err
	}
	return rawResult(raw), nil, nil
}

func (r *registry) categories(ctx context.Context, _ *mcp.CallToolRequest, in categoriesInput) (*mcp.CallToolResult, any, error) {
	raw, err := r.client.Categories(ctx, in.Category)
	if err != nil {
		return nil, nil, err
	}
	return rawResult(raw), nil, nil
}

func (r *registry) recentCaptures(ctx context.Context, _ *mcp.CallToolRequest, in recentInput) (*mcp.CallToolResult, recentOutput, error) {
	limit, err := checkPage(in.Limit, in.Offset)
	if err != nil {
		return nil, recentOutput{}, err
	}
	all, err := r.client.RecentCaptures(ctx, in.Timestamp)
	if err != nil {
		return nil, recentOutput{}, err
	}
	items, p := paginate(all, limit, in.Offset)
	return nil, recentOutput{Captures: items, page: p}, nil
}

func (r *registry) compareCaptures(ctx context.Context, _ *mcp.CallToolRequest, in compareInput) (*mcp.CallToolResult, any, error) {
	raw, err := r.client.CompareCaptures(ctx, in.CaptureLeft, in.CaptureRight, in.RessourcesIgnoreDomains, in.RessourcesIgnoreRegexes)
	if err != nil {
		return nil, nil, err
	}
	return rawResult(raw), nil, nil
}

func (r *registry) takedownInfo(ctx context.Context, _ *mcp.CallToolRequest, in takedownInput) (*mcp.CallToolResult, any, error) {
	raw, err := r.client.Takedown(ctx, in.CaptureUUID, in.Filter)
	if err != nil {
		return nil, nil, captureErr(err)
	}
	return rawResult(raw), nil, nil
}
