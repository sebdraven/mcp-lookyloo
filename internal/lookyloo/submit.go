package lookyloo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultWaitTimeout  = 120 * time.Second
	MaxWaitTimeout      = 3600 * time.Second
	DefaultPollInterval = 5 * time.Second
	MaxUnknownPolls     = 3
)

var Browsers = []string{"chromium", "firefox", "webkit"}

type AutoReport struct {
	Email   string `json:"email,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type SubmitParams struct {
	URL               string
	Document          string
	DocumentName      string
	Listing           bool
	AllowTracking     *bool
	JavaScriptEnabled *bool
	UserAgent         string
	BrowserName       string
	DeviceName        string
	Referer           string
	Headers           string
	Proxy             string
	Cookies           string
	AutoReport        *AutoReport
}

type submitFields struct {
	URL               string      `json:"url,omitempty"`
	Document          string      `json:"document,omitempty"`
	DocumentName      string      `json:"document_name,omitempty"`
	Listing           int         `json:"listing"`
	AllowTracking     *int        `json:"allow_tracking,omitempty"`
	JavaScriptEnabled *int        `json:"java_script_enabled,omitempty"`
	UserAgent         string      `json:"user_agent,omitempty"`
	BrowserName       string      `json:"browser_name,omitempty"`
	DeviceName        string      `json:"device_name,omitempty"`
	Referer           string      `json:"referer,omitempty"`
	Headers           string      `json:"headers,omitempty"`
	Proxy             string      `json:"proxy,omitempty"`
	Cookies           string      `json:"cookies,omitempty"`
	AutoReport        *AutoReport `json:"auto_report,omitempty"`
}

func boolInt(b *bool) *int {
	if b == nil {
		return nil
	}
	v := 0
	if *b {
		v = 1
	}
	return &v
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

func (p SubmitParams) fields() (submitFields, error) {
	u := strings.TrimSpace(p.URL)
	doc := strings.TrimSpace(p.Document)
	if (u == "") == (doc == "") {
		return submitFields{}, errors.New("lookyloo submit: give exactly one of url, document or document_path")
	}
	f := submitFields{
		URL:               u,
		AllowTracking:     boolInt(p.AllowTracking),
		JavaScriptEnabled: boolInt(p.JavaScriptEnabled),
		UserAgent:         strings.TrimSpace(p.UserAgent),
		DeviceName:        strings.TrimSpace(p.DeviceName),
		Referer:           strings.TrimSpace(p.Referer),
		Headers:           p.Headers,
		Proxy:             strings.TrimSpace(p.Proxy),
		Cookies:           p.Cookies,
		AutoReport:        p.AutoReport,
	}
	if p.Listing {
		f.Listing = 1
	}
	if u != "" && (hasControl(u) || strings.ContainsAny(u, " \t")) {
		return submitFields{}, fmt.Errorf("lookyloo submit: %q is not a URL", u)
	}
	if doc != "" {
		if _, err := base64.StdEncoding.DecodeString(doc); err != nil {
			return submitFields{}, errors.New("lookyloo submit: document is not valid base64")
		}
		name := strings.TrimSpace(p.DocumentName)
		if name == "" || hasControl(name) || strings.ContainsAny(name, `/\`) {
			return submitFields{}, errors.New("lookyloo submit: a document needs a plain document_name, e.g. invoice.html")
		}
		f.Document, f.DocumentName = doc, name
	}
	if b := strings.ToLower(strings.TrimSpace(p.BrowserName)); b != "" {
		if !slices.Contains(Browsers, b) {
			return submitFields{}, fmt.Errorf("lookyloo submit: browser_name must be one of %s", strings.Join(Browsers, ", "))
		}
		f.BrowserName = b
	}
	if f.Proxy != "" {
		pu, err := url.Parse(f.Proxy)
		if err != nil || pu.Scheme == "" || pu.Host == "" {
			return submitFields{}, errors.New("lookyloo submit: proxy must look like scheme://[user:password@]host:port")
		}
	}
	if f.Cookies != "" && !json.Valid([]byte(f.Cookies)) {
		return submitFields{}, errors.New("lookyloo submit: cookies must be a JSON export of a list of cookies")
	}
	return f, nil
}

func (c *Client) Submit(ctx context.Context, p SubmitParams) (string, error) {
	f, err := p.fields()
	if err != nil {
		return "", err
	}
	id, err := c.submit(ctx, f)
	return id, redactProxy(err, f.Proxy)
}

func (c *Client) submit(ctx context.Context, f submitFields) (string, error) {
	resp, err := c.do(ctx, request{method: http.MethodPost, path: "/submit", body: f, auth: authOptional})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("lookyloo POST /submit: reading the response: %w", err)
	}
	return ParseSubmitResponse(b)
}

// ParseSubmitResponse accepts the UUID bare or as a JSON string: /submit is declared text/text but answers application/json.
func ParseSubmitResponse(b []byte) (string, error) {
	s := string(bytes.TrimSpace(b))
	var quoted string
	if err := json.Unmarshal([]byte(s), &quoted); err == nil {
		s = strings.TrimSpace(quoted)
	}
	id, err := NormaliseUUID(s)
	if err != nil {
		if le := errorEnvelope([]byte(s)); le != nil {
			return "", fmt.Errorf("lookyloo POST /submit: %s", le.Message)
		}
		return "", fmt.Errorf("lookyloo POST /submit: the response is not a capture UUID: %s", truncate(s, 200))
	}
	return id, nil
}

func redactProxy(err error, proxy string) error {
	if err == nil || proxy == "" {
		return err
	}
	secrets := []string{proxy}
	if pu, perr := url.Parse(proxy); perr == nil && pu.User != nil {
		secrets = append(secrets, pu.User.String(), pu.User.Username())
		if pw, ok := pu.User.Password(); ok {
			secrets = append(secrets, pw)
		}
	}
	msg := err.Error()
	clean := msg
	for _, s := range secrets {
		if s != "" {
			clean = strings.ReplaceAll(clean, s, "[redacted]")
		}
	}
	if clean == msg {
		return err
	}
	return errors.New(clean)
}

type WaitOutcome string

const (
	OutcomeDone     WaitOutcome = "done"
	OutcomeTimedOut WaitOutcome = "timed_out"
)

type WaitResult struct {
	Outcome    WaitOutcome
	StatusCode int
	Error      string
	Polls      int
}

var ErrPersistentUnknown = errors.New("the instance reported the capture as unknown")

// Wait polls the status as spec/capture_lifecycle.qnt does: at most timeout/interval+1 polls.
func (c *Client) Wait(ctx context.Context, uuid string, timeout time.Duration) (WaitResult, error) {
	id, err := NormaliseUUID(uuid)
	if err != nil {
		return WaitResult{}, err
	}
	if timeout <= 0 || timeout > MaxWaitTimeout {
		return WaitResult{}, fmt.Errorf("lookyloo: wait_timeout must be between 1s and %s", MaxWaitTimeout)
	}
	interval := c.pollInterval
	maxPolls := int(timeout/interval) + 1
	var res WaitResult
	unknown := 0
	for {
		st, err := c.CaptureStatus(ctx, id, true)
		if err != nil {
			return res, err
		}
		res.Polls++
		res.StatusCode, res.Error = st.StatusCode, st.Error
		if st.StatusCode == StatusDone {
			res.Outcome = OutcomeDone
			return res, nil
		}
		if st.StatusCode == StatusUnknown {
			unknown++
			if unknown >= MaxUnknownPolls {
				return res, fmt.Errorf("lookyloo: %w: %s answered status -1 on %d consecutive polls", ErrPersistentUnknown, id, unknown)
			}
		} else {
			unknown = 0
		}
		if res.Polls >= maxPolls {
			res.Outcome = OutcomeTimedOut
			return res, nil
		}
		if err := c.sleep(ctx, interval); err != nil {
			return res, err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func WithPollInterval(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.pollInterval = d
		}
	}
}

type triggerModulesFields struct {
	Force bool `json:"force"`
}

func (c *Client) TriggerModules(ctx context.Context, uuid string, force bool) (json.RawMessage, error) {
	path, err := capturePath("/json/", uuid, "/trigger_modules")
	if err != nil {
		return nil, err
	}
	return c.doJSON(ctx, request{method: http.MethodPost, path: path, body: triggerModulesFields{Force: force}, auth: authOptional})
}
