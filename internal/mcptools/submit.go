package mcptools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
)

const maxDocumentBytes = 64 << 20

type autoReportInput struct {
	Email   string `json:"email,omitempty" jsonschema:"email of the reporter, for the analyst to get in touch"`
	Comment string `json:"comment,omitempty" jsonschema:"description of the URL for the analyst"`
}

type submitInput struct {
	URL               string           `json:"url,omitempty" jsonschema:"URL to capture; give exactly one of url, document_path, document"`
	DocumentPath      string           `json:"document_path,omitempty" jsonschema:"local file to capture (HTML, PDF...); the server reads and base64-encodes it"`
	Document          string           `json:"document,omitempty" jsonschema:"base64 of a document to capture; needs document_name"`
	DocumentName      string           `json:"document_name,omitempty" jsonschema:"name of the document (default: the base name of document_path)"`
	Listing           bool             `json:"listing,omitempty" jsonschema:"show the capture on the public index of the instance (default false)"`
	AllowTracking     *bool            `json:"allow_tracking,omitempty" jsonschema:"let the site track the browser (Lookyloo default true)"`
	JavaScriptEnabled *bool            `json:"java_script_enabled,omitempty" jsonschema:"run JavaScript (Lookyloo default true)"`
	UserAgent         string           `json:"user_agent,omitempty" jsonschema:"user agent string"`
	BrowserName       string           `json:"browser_name,omitempty" jsonschema:"chromium, firefox or webkit"`
	DeviceName        string           `json:"device_name,omitempty" jsonschema:"a device from lk_devices, e.g. Desktop Chrome HiDPI"`
	Referer           string           `json:"referer,omitempty" jsonschema:"referer to send"`
	Headers           string           `json:"headers,omitempty" jsonschema:"extra headers, e.g. Accept-Language: en-US;q=0.5, fr-FR;q=0.4"`
	Proxy             string           `json:"proxy,omitempty" jsonschema:"proxy for the capture, scheme://[user:password@]host:port; never logged nor returned"`
	Cookies           string           `json:"cookies,omitempty" jsonschema:"JSON export of a list of cookies, e.g. from lk_capture_cookies"`
	AutoReport        *autoReportInput `json:"auto_report,omitempty" jsonschema:"have Lookyloo email the capture to its investigation team when done; needs -allow-push"`
	Wait              bool             `json:"wait,omitempty" jsonschema:"poll the status until the capture is done, unknown or wait_timeout is reached"`
	WaitTimeout       int              `json:"wait_timeout,omitempty" jsonschema:"seconds to wait for, 1 to 3600 (default 120)"`
}

type submitOutput struct {
	CaptureUUID  string         `json:"capture_uuid"`
	Listing      bool           `json:"listing"`
	Outcome      string         `json:"outcome"`
	StatusCode   *int           `json:"status_code,omitempty"`
	CaptureError string         `json:"capture_error,omitempty"`
	Polls        int            `json:"polls,omitempty"`
	Info         map[string]any `json:"info,omitempty"`
}

type triggerInput struct {
	CaptureUUID string `json:"capture_uuid" jsonschema:"UUID of the capture"`
	Force       bool   `json:"force,omitempty" jsonschema:"run the modules again even if their results are cached"`
}

func (r *registry) submitTools(s *mcp.Server) {
	addTool(r, s, &mcp.Tool{
		Name: "lk_submit",
		Description: "Submit a URL or a document to the instance for a new capture; returns its UUID. " +
			"The capture is NOT listed on the public index unless listing is true. " +
			"With wait, polls the status every few seconds until done (then returns lk_capture_info), until the instance reports the UUID unknown 3 times in a row (error), or until wait_timeout (outcome timed_out). " +
			"The browser of the instance visits the URL: never submit a URL that carries a secret.",
	}, r.submit)

	addTool(r, s, &mcp.Tool{
		Name: "lk_trigger_modules",
		Description: "Run the third-party modules configured on the instance (e.g. VirusTotal, PhishTank, URLhaus) on a capture; " +
			"read their answers with lk_capture_modules. force re-runs them even if cached.",
	}, r.triggerModules)
}

func readDocument(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("document_path: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxDocumentBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("document_path: %w", err)
	}
	if len(b) > maxDocumentBytes {
		return "", "", fmt.Errorf("document_path: the file is larger than %d bytes", maxDocumentBytes)
	}
	return base64.StdEncoding.EncodeToString(b), filepath.Base(path), nil
}

func (r *registry) submit(ctx context.Context, _ *mcp.CallToolRequest, in submitInput) (*mcp.CallToolResult, submitOutput, error) {
	sources := 0
	for _, v := range []string{in.URL, in.DocumentPath, in.Document} {
		if strings.TrimSpace(v) != "" {
			sources++
		}
	}
	if sources != 1 {
		return nil, submitOutput{}, errors.New("give exactly one of url, document_path or document")
	}
	if in.AutoReport != nil && !r.opts.allows(Push) {
		return nil, submitOutput{}, errors.New("auto_report makes Lookyloo email its investigation team, an effect outside the instance: start the server with -allow-push to use it")
	}
	timeout := lookyloo.DefaultWaitTimeout
	if in.WaitTimeout != 0 {
		if in.WaitTimeout < 0 || time.Duration(in.WaitTimeout)*time.Second > lookyloo.MaxWaitTimeout {
			return nil, submitOutput{}, fmt.Errorf("wait_timeout must be between 1 and %d seconds", int(lookyloo.MaxWaitTimeout/time.Second))
		}
		timeout = time.Duration(in.WaitTimeout) * time.Second
	}

	p := lookyloo.SubmitParams{
		URL:               in.URL,
		Document:          in.Document,
		DocumentName:      in.DocumentName,
		Listing:           in.Listing,
		AllowTracking:     in.AllowTracking,
		JavaScriptEnabled: in.JavaScriptEnabled,
		UserAgent:         in.UserAgent,
		BrowserName:       in.BrowserName,
		DeviceName:        in.DeviceName,
		Referer:           in.Referer,
		Headers:           in.Headers,
		Proxy:             in.Proxy,
		Cookies:           in.Cookies,
	}
	if in.AutoReport != nil {
		p.AutoReport = &lookyloo.AutoReport{Email: in.AutoReport.Email, Comment: in.AutoReport.Comment}
	}
	if path := strings.TrimSpace(in.DocumentPath); path != "" {
		doc, name, err := readDocument(path)
		if err != nil {
			return nil, submitOutput{}, err
		}
		p.Document = doc
		if strings.TrimSpace(p.DocumentName) == "" {
			p.DocumentName = name
		}
	}

	id, err := r.client.Submit(ctx, p)
	if err != nil {
		return nil, submitOutput{}, err
	}
	out := submitOutput{CaptureUUID: id, Listing: in.Listing, Outcome: "submitted"}
	if !in.Wait {
		return nil, out, nil
	}

	w, err := r.client.Wait(ctx, id, timeout)
	if err != nil {
		return nil, submitOutput{}, fmt.Errorf("capture %s was submitted, but waiting failed: %w", id, err)
	}
	out.Outcome, out.Polls, out.CaptureError = string(w.Outcome), w.Polls, w.Error
	out.StatusCode = &w.StatusCode
	if w.Outcome == lookyloo.OutcomeDone {
		raw, err := r.client.CaptureInfo(ctx, id)
		if err != nil {
			return nil, submitOutput{}, fmt.Errorf("capture %s is done, but reading its info failed: %w", id, err)
		}
		if err := json.Unmarshal(raw, &out.Info); err != nil {
			return nil, submitOutput{}, fmt.Errorf("capture %s: decoding its info: %w", id, err)
		}
	}
	return nil, out, nil
}

func (r *registry) triggerModules(ctx context.Context, _ *mcp.CallToolRequest, in triggerInput) (*mcp.CallToolResult, any, error) {
	raw, err := r.client.TriggerModules(ctx, in.CaptureUUID, in.Force)
	if err != nil {
		return nil, nil, captureErr(err)
	}
	return rawResult(raw), nil, nil
}
