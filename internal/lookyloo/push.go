package lookyloo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var instanceNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type reportFields struct {
	Email   string `json:"email,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// CaptureReport sends the JSON body genericapi.py reads (request.get_json), not the query parameters the swagger lists.
func (c *Client) CaptureReport(ctx context.Context, uuid, email, comment string) (json.RawMessage, error) {
	path, err := capturePath("/json/", uuid, "/report")
	if err != nil {
		return nil, err
	}
	if hasControl(email) || strings.ContainsAny(email, " ,;") {
		return nil, fmt.Errorf("lookyloo report: %q is not an email address", email)
	}
	return c.doJSON(ctx, request{method: http.MethodPost, path: path, body: reportFields{Email: strings.TrimSpace(email), Comment: comment}, auth: authOptional})
}

type mispPushFields struct {
	AllowDuplicates int `json:"allow_duplicates"`
	WithParents     int `json:"with_parents"`
}

func (c *Client) MISPPush(ctx context.Context, uuid, instance string, allowDuplicates, withParents bool) (json.RawMessage, error) {
	suffix := "/misp_push"
	if name := strings.TrimSpace(instance); name != "" {
		if !instanceNameRe.MatchString(name) {
			return nil, fmt.Errorf("lookyloo misp_push: %q is not a MISP instance name", instance)
		}
		suffix += "/" + url.PathEscape(name)
	}
	path, err := capturePath("/json/", uuid, suffix)
	if err != nil {
		return nil, err
	}
	body := mispPushFields{AllowDuplicates: *boolInt(&allowDuplicates), WithParents: *boolInt(&withParents)}
	return c.doJSON(ctx, request{method: http.MethodPost, path: path, body: body, auth: authRequired, bulk: true})
}

// UploadParams follows UploadCapture.post in website/web/genericapi.py (Lookyloo v1.27.0).
type UploadParams struct {
	Listing     bool
	FullCapture []byte
	HAR         []byte
	LandingPage string
	Screenshot  []byte
	HTML        []byte
}

type uploadFields struct {
	Listing        int    `json:"listing"`
	FullCapture    string `json:"full_capture,omitempty"`
	HARFile        string `json:"har_file,omitempty"`
	LandingPage    string `json:"landing_page,omitempty"`
	ScreenshotFile string `json:"screenshot_file,omitempty"`
	HTMLFile       string `json:"html_file,omitempty"`
}

type UploadResult struct {
	UUID     string         `json:"uuid"`
	Messages map[string]any `json:"messages,omitempty"`
}

func (p UploadParams) fields() (uploadFields, error) {
	if (len(p.FullCapture) == 0) == (len(p.HAR) == 0) {
		return uploadFields{}, errors.New("lookyloo upload: give exactly one of a full capture (ZIP export) or a HAR file")
	}
	f := uploadFields{}
	if p.Listing {
		f.Listing = 1
	}
	b64 := base64.StdEncoding.EncodeToString
	if len(p.FullCapture) > 0 {
		if !bytes.HasPrefix(p.FullCapture, zipMagic) {
			return uploadFields{}, errors.New("lookyloo upload: the full capture is not a ZIP (an lk_capture_export archive)")
		}
		if len(p.Screenshot) > 0 || len(p.HTML) > 0 || p.LandingPage != "" {
			return uploadFields{}, errors.New("lookyloo upload: landing_page, screenshot and html go with a HAR file, not a full capture")
		}
		f.FullCapture = b64(p.FullCapture)
		return f, nil
	}
	if !json.Valid(p.HAR) && !bytes.HasPrefix(p.HAR, []byte{0x1f, 0x8b}) {
		return uploadFields{}, errors.New("lookyloo upload: the HAR file is neither JSON nor gzip")
	}
	if len(p.Screenshot) > 0 && !bytes.HasPrefix(p.Screenshot, pngMagic) {
		return uploadFields{}, errors.New("lookyloo upload: the screenshot is not a PNG")
	}
	f.HARFile = b64(p.HAR)
	f.LandingPage = strings.TrimSpace(p.LandingPage)
	if len(p.Screenshot) > 0 {
		f.ScreenshotFile = b64(p.Screenshot)
	}
	if len(p.HTML) > 0 {
		f.HTMLFile = b64(p.HTML)
	}
	return f, nil
}

func (c *Client) UploadCapture(ctx context.Context, p UploadParams) (UploadResult, error) {
	f, err := p.fields()
	if err != nil {
		return UploadResult{}, err
	}
	raw, err := c.doJSON(ctx, request{method: http.MethodPost, path: "/json/upload", body: f, auth: authOptional, bulk: true})
	if err != nil {
		return UploadResult{}, err
	}
	var out UploadResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return UploadResult{}, fmt.Errorf("lookyloo upload: decoding the response: %w", err)
	}
	id, err := NormaliseUUID(out.UUID)
	if err != nil {
		return UploadResult{}, fmt.Errorf("lookyloo upload: the response has no capture UUID: %s", truncate(string(raw), 200))
	}
	out.UUID = id
	return out, nil
}
