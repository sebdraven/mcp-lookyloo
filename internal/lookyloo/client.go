// Package lookyloo is a client for the Lookyloo REST API.
package lookyloo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultTimeout   = 60 * time.Second
	ArtefactTimeout  = 300 * time.Second
	maxErrorBodyLen  = 512
	maxJSONBodyBytes = 256 << 20
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Client struct {
	baseURL      string
	userAgent    string
	http         *http.Client
	bulk         *http.Client
	tokens       TokenSource
	pollInterval time.Duration
	sleep        func(context.Context, time.Duration) error
}

type Option func(*Client)

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

func WithArtefactHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.bulk = h }
}

func WithVersion(v string) Option {
	return func(c *Client) { c.userAgent = "mcp-lookyloo/" + v }
}

func WithTokenSource(ts TokenSource) Option {
	return func(c *Client) { c.tokens = ts }
}

func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:   strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		userAgent: "mcp-lookyloo/dev",
		http:      &http.Client{Timeout: DefaultTimeout},
		bulk:      &http.Client{Timeout: ArtefactTimeout},

		pollInterval: DefaultPollInterval,
		sleep:        sleepCtx,
	}
	for _, o := range opts {
		o(c)
	}
	if c.tokens == nil {
		c.tokens = NewResolver(c.GetToken)
	}
	return c
}

func (c *Client) BaseURL() string { return c.baseURL }

type authMode int

const (
	authNone authMode = iota
	authOptional
	authRequired
)

type request struct {
	method string
	path   string
	query  url.Values
	body   any
	header http.Header
	auth   authMode
	bulk   bool
}

type APIError struct {
	StatusCode int
	Method     string
	Path       string
	Body       string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("lookyloo %s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	switch e.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		msg += " (authentication rejected or required)"
	case http.StatusNotFound:
		msg += " (not found)"
	}
	if b := strings.TrimSpace(e.Body); b != "" {
		msg += ": " + b
	}
	return msg
}

// LookylooError is an error Lookyloo reports in a JSON body, often with HTTP 200.
type LookylooError struct {
	Method  string
	Path    string
	Message string
	Details json.RawMessage
}

func (e *LookylooError) Error() string {
	msg := fmt.Sprintf("lookyloo %s %s: %s", e.Method, e.Path, e.Message)
	if len(e.Details) > 0 && string(e.Details) != "null" {
		msg += " (details: " + string(e.Details) + ")"
	}
	return msg
}

func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	token, err := c.token(ctx, r.auth)
	if err != nil {
		return nil, fmt.Errorf("lookyloo %s %s: %w", r.method, r.path, err)
	}

	u := c.baseURL + r.path
	if len(r.query) > 0 {
		u += "?" + r.query.Encode()
	}
	var body io.Reader
	if r.body != nil {
		b, err := json.Marshal(r.body)
		if err != nil {
			return nil, fmt.Errorf("lookyloo %s %s: encoding the request: %w", r.method, r.path, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range r.header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("User-Agent", c.userAgent)
	if r.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	hc := c.http
	if r.bulk {
		hc = c.bulk
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lookyloo %s %s: %w", r.method, r.path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyLen))
		resp.Body.Close()
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Method:     r.method,
			Path:       r.path,
			Body:       string(b),
		}
	}
	return resp, nil
}

func (c *Client) token(ctx context.Context, mode authMode) (string, error) {
	if mode == authNone {
		return "", nil
	}
	t, err := c.tokens.Token(ctx)
	if err == nil && t != "" {
		return t, nil
	}
	if mode == authRequired {
		if err == nil {
			err = ErrNoToken
		}
		return "", err
	}
	return "", nil
}

func (c *Client) doJSON(ctx context.Context, r request) (json.RawMessage, error) {
	resp, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("lookyloo %s %s: reading the response: %w", r.method, r.path, err)
	}
	if len(b) > maxJSONBodyBytes {
		return nil, fmt.Errorf("lookyloo %s %s: the response is larger than %d bytes", r.method, r.path, maxJSONBodyBytes)
	}
	b = bytes.TrimSpace(b)
	if !json.Valid(b) {
		return nil, fmt.Errorf("lookyloo %s %s: the response is not JSON: %s", r.method, r.path, truncate(string(b), maxErrorBodyLen))
	}
	if le := errorEnvelope(b); le != nil {
		le.Method, le.Path = r.method, r.path
		return nil, le
	}
	return json.RawMessage(b), nil
}

func errorEnvelope(b []byte) *LookylooError {
	if len(b) == 0 || b[0] != '{' {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	raw, ok := m["error"]
	if !ok {
		return nil
	}
	for k := range m {
		if k != "error" && k != "details" {
			return nil
		}
	}
	le := &LookylooError{Details: m["details"]}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		le.Message = s
	} else {
		le.Message = string(raw)
	}
	return le
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func NormaliseUUID(s string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(s))
	if !uuidRe.MatchString(id) {
		return "", fmt.Errorf("lookyloo: %q is not a capture UUID", s)
	}
	return id, nil
}
