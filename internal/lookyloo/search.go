package lookyloo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	sha512Re   = regexp.MustCompile(`^[0-9a-f]{128}$`)
	tldRe      = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)*$`)
	categoryRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]+$`)
)

func NormaliseSHA512(h string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(h))
	if !sha512Re.MatchString(s) {
		return "", fmt.Errorf("lookyloo: %q is not a complete SHA512 (128 hexadecimal characters)", h)
	}
	return s, nil
}

func checkTimestamp(name, v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return "", fmt.Errorf("lookyloo: %s %q is not a Unix timestamp in seconds", name, v)
	}
	return v, nil
}

type occurrenceQuery struct {
	URL                string `json:"url,omitempty"`
	Hostname           string `json:"hostname,omitempty"`
	Limit              int    `json:"limit"`
	CachedCapturesOnly bool   `json:"cached_captures_only"`
}

func (c *Client) occurrences(ctx context.Context, path string, q occurrenceQuery) ([]map[string]any, error) {
	if q.Limit < 1 {
		return nil, errors.New("lookyloo: limit must be at least 1")
	}
	raw, err := c.doJSON(ctx, request{method: http.MethodPost, path: path, body: q, auth: authOptional, bulk: !q.CachedCapturesOnly})
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("lookyloo %s: decoding the response: %w", path, err)
	}
	return out, nil
}

func (c *Client) URLInfo(ctx context.Context, u string, limit int, cachedOnly bool) ([]map[string]any, error) {
	u = strings.TrimSpace(u)
	if u == "" {
		return nil, errors.New("lookyloo url_info: a URL is required")
	}
	return c.occurrences(ctx, "/json/url_info", occurrenceQuery{URL: u, Limit: limit, CachedCapturesOnly: cachedOnly})
}

func (c *Client) HostnameInfo(ctx context.Context, hostname string, limit int, cachedOnly bool) ([]map[string]any, error) {
	h := strings.TrimSpace(hostname)
	if !hostnameRe.MatchString(h) {
		return nil, fmt.Errorf("lookyloo hostname_info: %q is not a hostname", hostname)
	}
	return c.occurrences(ctx, "/json/hostname_info", occurrenceQuery{Hostname: h, Limit: limit, CachedCapturesOnly: cachedOnly})
}

func (c *Client) HashInfo(ctx context.Context, h string) (json.RawMessage, error) {
	s, err := NormaliseSHA512(h)
	if err != nil {
		return nil, err
	}
	return c.doJSON(ctx, request{method: http.MethodGet, path: "/json/hash_info/" + s, auth: authOptional})
}

type TLDQuery struct {
	TLD               string
	OldestCapture     string
	MostRecentCapture string
	URLsOnly          bool
}

func (c *Client) TLDCaptures(ctx context.Context, p TLDQuery) (json.RawMessage, error) {
	q := url.Values{}
	tld := strings.ToLower(strings.Trim(strings.TrimSpace(p.TLD), "."))
	if tld != "" {
		if !tldRe.MatchString(tld) {
			return nil, fmt.Errorf("lookyloo tlds: %q is not a TLD", p.TLD)
		}
		q.Set("tld", tld)
	} else if p.URLsOnly || p.OldestCapture != "" || p.MostRecentCapture != "" {
		return nil, errors.New("lookyloo tlds: urls_only, oldest_capture and most_recent_capture need a tld")
	}
	oldest, err := checkTimestamp("oldest_capture", p.OldestCapture)
	if err != nil {
		return nil, err
	}
	recent, err := checkTimestamp("most_recent_capture", p.MostRecentCapture)
	if err != nil {
		return nil, err
	}
	if oldest != "" {
		q.Set("oldest_capture", oldest)
	}
	if recent != "" {
		q.Set("most_recent_capture", recent)
	}
	if p.URLsOnly {
		q.Set("urls_only", "1")
	}
	return c.doJSON(ctx, request{method: http.MethodGet, path: "/json/tlds", query: q, auth: authOptional, bulk: true})
}

func (c *Client) Categories(ctx context.Context, category string) (json.RawMessage, error) {
	path := "/json/categories"
	if cat := strings.TrimSpace(category); cat != "" {
		if !categoryRe.MatchString(cat) {
			return nil, fmt.Errorf("lookyloo categories: %q is not a category name", category)
		}
		path += "/" + url.PathEscape(cat)
	}
	return c.doJSON(ctx, request{method: http.MethodGet, path: path, auth: authOptional, bulk: true})
}

func (c *Client) RecentCaptures(ctx context.Context, timestamp string) ([]string, error) {
	ts, err := checkTimestamp("timestamp", timestamp)
	if err != nil {
		return nil, err
	}
	path := "/json/recent_captures"
	if ts != "" {
		path += "/" + url.PathEscape(ts)
	}
	raw, err := c.doJSON(ctx, request{method: http.MethodGet, path: path, auth: authOptional, bulk: true})
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("lookyloo recent_captures: decoding the response: %w", err)
	}
	return out, nil
}

type compareSettings struct {
	IgnoreDomains []string `json:"ressources_ignore_domains,omitempty"`
	IgnoreRegexes []string `json:"ressources_ignore_regexes,omitempty"`
}

type compareFields struct {
	Left     string           `json:"capture_left"`
	Right    string           `json:"capture_right"`
	Settings *compareSettings `json:"compare_settings,omitempty"`
}

func (c *Client) CompareCaptures(ctx context.Context, left, right string, ignoreDomains, ignoreRegexes []string) (json.RawMessage, error) {
	l, err := NormaliseUUID(left)
	if err != nil {
		return nil, err
	}
	r, err := NormaliseUUID(right)
	if err != nil {
		return nil, err
	}
	body := compareFields{Left: l, Right: r}
	if len(ignoreDomains) > 0 || len(ignoreRegexes) > 0 {
		body.Settings = &compareSettings{IgnoreDomains: ignoreDomains, IgnoreRegexes: ignoreRegexes}
	}
	return c.doJSON(ctx, request{method: http.MethodPost, path: "/json/compare_captures", body: body, auth: authOptional, bulk: true})
}

type takedownFields struct {
	CaptureUUID string `json:"capture_uuid"`
	Filter      bool   `json:"filter"`
}

func (c *Client) Takedown(ctx context.Context, uuid string, filter bool) (json.RawMessage, error) {
	id, err := NormaliseUUID(uuid)
	if err != nil {
		return nil, err
	}
	return c.doJSON(ctx, request{method: http.MethodPost, path: "/json/takedown", body: takedownFields{CaptureUUID: id, Filter: filter}, auth: authOptional})
}
