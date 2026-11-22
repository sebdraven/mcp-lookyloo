package lookyloo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const (
	StatusUnknown = -1
	StatusQueued  = 0
	StatusDone    = 1
	StatusOngoing = 2
)

var HashAlgorithms = []string{
	"blake2b", "blake2s", "md5", "md5-sha1", "ripemd160", "sha1", "sha224", "sha256", "sha384",
	"sha3_224", "sha3_256", "sha3_384", "sha3_512", "sha512", "sha512_224", "sha512_256", "sm3",
}

var fieldsMaskRe = regexp.MustCompile(`^[A-Za-z0-9_,{}* ]+$`)

type CaptureStatus struct {
	StatusCode int    `json:"status_code"`
	Error      string `json:"error,omitempty"`
}

type CaptureHashes struct {
	Hashes         []string            `json:"hashes"`
	HashesWithURLs map[string][]string `json:"hashes_with_urls,omitempty"`
}

func capturePath(prefix, uuid, suffix string) (string, error) {
	id, err := NormaliseUUID(uuid)
	if err != nil {
		return "", err
	}
	return prefix + id + suffix, nil
}

func (c *Client) captureJSON(ctx context.Context, uuid, suffix string, q url.Values, h http.Header) (json.RawMessage, error) {
	path, err := capturePath("/json/", uuid, suffix)
	if err != nil {
		return nil, err
	}
	return c.doJSON(ctx, request{method: http.MethodGet, path: path, query: q, header: h, auth: authOptional})
}

func (c *Client) CaptureInfo(ctx context.Context, uuid string) (json.RawMessage, error) {
	return c.captureJSON(ctx, uuid, "/info", nil, nil)
}

func (c *Client) CaptureStatus(ctx context.Context, uuid string, withError bool) (CaptureStatus, error) {
	q := url.Values{}
	if withError {
		q.Set("with_error", "1")
	}
	raw, err := c.captureJSON(ctx, uuid, "/status", q, nil)
	if err != nil {
		return CaptureStatus{}, err
	}
	var st CaptureStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return CaptureStatus{}, fmt.Errorf("lookyloo status: decoding %s: %w", truncate(string(raw), maxErrorBodyLen), err)
	}
	return st, nil
}

func (c *Client) CaptureStats(ctx context.Context, uuid string) (json.RawMessage, error) {
	return c.captureJSON(ctx, uuid, "/stats", nil, nil)
}

func (c *Client) CaptureRedirects(ctx context.Context, uuid string) (json.RawMessage, error) {
	return c.captureJSON(ctx, uuid, "/redirects", nil, nil)
}

func (c *Client) CaptureCookies(ctx context.Context, uuid string) (json.RawMessage, error) {
	return c.captureJSON(ctx, uuid, "/cookies", nil, nil)
}

func (c *Client) CaptureModules(ctx context.Context, uuid string) (json.RawMessage, error) {
	return c.captureJSON(ctx, uuid, "/modules", nil, nil)
}

func (c *Client) CaptureMISPExport(ctx context.Context, uuid string) (json.RawMessage, error) {
	return c.captureJSON(ctx, uuid, "/misp_export", nil, nil)
}

func (c *Client) CaptureComparables(ctx context.Context, uuid, fields string) (json.RawMessage, error) {
	var h http.Header
	if f := strings.TrimSpace(fields); f != "" {
		if !fieldsMaskRe.MatchString(f) {
			return nil, fmt.Errorf("lookyloo comparables: %q is not a fields mask (e.g. root_url,final_url or redirects{length})", fields)
		}
		h = http.Header{"X-Fields": {f}}
	}
	return c.captureJSON(ctx, uuid, "/comparables", nil, h)
}

func (c *Client) CaptureURLs(ctx context.Context, uuid string) ([]string, error) {
	var out struct {
		Response struct {
			URLs []string `json:"urls"`
		} `json:"response"`
	}
	if err := c.captureDecode(ctx, uuid, "/urls", nil, &out); err != nil {
		return nil, err
	}
	return out.Response.URLs, nil
}

func (c *Client) CaptureHostnames(ctx context.Context, uuid string) ([]string, error) {
	var out struct {
		Response struct {
			Hostnames []string `json:"hostnames"`
		} `json:"response"`
	}
	if err := c.captureDecode(ctx, uuid, "/hostnames", nil, &out); err != nil {
		return nil, err
	}
	return out.Response.Hostnames, nil
}

func (c *Client) CaptureHashes(ctx context.Context, uuid, algorithm string, hashesOnly bool) (CaptureHashes, error) {
	algo := strings.ToLower(strings.TrimSpace(algorithm))
	if algo == "" {
		algo = "sha512"
	}
	if !slices.Contains(HashAlgorithms, algo) {
		return CaptureHashes{}, fmt.Errorf("lookyloo hashes: unsupported algorithm %q (one of %s)", algorithm, strings.Join(HashAlgorithms, ", "))
	}
	q := url.Values{"algorithm": {algo}}
	if !hashesOnly {
		q.Set("hashes_only", "0")
	}
	var out struct {
		Response CaptureHashes `json:"response"`
	}
	if err := c.captureDecode(ctx, uuid, "/hashes", q, &out); err != nil {
		return CaptureHashes{}, err
	}
	return out.Response, nil
}

func (c *Client) captureDecode(ctx context.Context, uuid, suffix string, q url.Values, v any) error {
	raw, err := c.captureJSON(ctx, uuid, suffix, q, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("lookyloo %s: decoding the response: %w", strings.TrimPrefix(suffix, "/"), err)
	}
	return nil
}
