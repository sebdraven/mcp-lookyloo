package mcptools

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var submitTools = []string{"lk_submit", "lk_trigger_modules"}

const (
	statusOngoing = `{"status_code": 2}`
	statusDone    = `{"status_code": 1}`
	statusUnknown = `{"status_code": -1}`
)

type submitResult struct {
	CaptureUUID  string         `json:"capture_uuid"`
	Listing      bool           `json:"listing"`
	Outcome      string         `json:"outcome"`
	StatusCode   *int           `json:"status_code"`
	CaptureError string         `json:"capture_error"`
	Polls        int            `json:"polls"`
	Info         map[string]any `json:"info"`
}

func submitRoutes(statuses ...string) map[string]reply {
	return map[string]reply{
		"POST /submit":                         {fixture: "submit_response.txt"},
		"GET /json/" + captureUUID + "/status": {bodies: statuses},
		"GET /json/" + captureUUID + "/info":   {fixture: "capture_info.json"},
	}
}

func submitBody(t *testing.T, e *env) map[string]any {
	t.Helper()
	for _, r := range e.fake.requests() {
		if r.path == "/submit" {
			var body map[string]any
			if err := json.Unmarshal(r.body, &body); err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatal("nothing was submitted")
	return nil
}

func count(e *env, path string) int {
	n := 0
	for _, r := range e.fake.requests() {
		if r.path == path {
			n++
		}
	}
	return n
}

func TestSubmitIsUnlistedByDefault(t *testing.T) {
	e := start(t, submitRoutes(statusDone), "", Options{})
	var out submitResult
	decode(t, e.call(t, "lk_submit", map[string]any{"url": "https://example.com/"}), &out)
	if out.CaptureUUID != captureUUID || out.Listing || out.Outcome != "submitted" || out.StatusCode != nil {
		t.Errorf("submit = %+v", out)
	}
	body := submitBody(t, e)
	if body["listing"] != float64(0) || body["url"] != "https://example.com/" {
		t.Errorf("body = %v", body)
	}
	if n := len(e.fake.requests()); n != 1 {
		t.Errorf("%d requests without wait, want 1", n)
	}
}

func TestSubmitListingOnRequest(t *testing.T) {
	e := start(t, submitRoutes(statusDone), "", Options{})
	var out submitResult
	decode(t, e.call(t, "lk_submit", map[string]any{"url": "https://example.com/", "listing": true}), &out)
	if !out.Listing || submitBody(t, e)["listing"] != float64(1) {
		t.Errorf("submit = %+v, body %v", out, submitBody(t, e))
	}
}

func TestSubmitWaitUntilDone(t *testing.T) {
	e := start(t, submitRoutes(statusOngoing, statusDone), "", Options{})
	var out submitResult
	decode(t, e.call(t, "lk_submit", map[string]any{"url": "https://example.com/", "wait": true}), &out)
	if out.Outcome != "done" || out.StatusCode == nil || *out.StatusCode != 1 || out.Polls != 2 {
		t.Fatalf("submit = %+v", out)
	}
	if out.Info["title"] != "Example Domain" || out.Info["uuid"] != captureUUID {
		t.Errorf("info = %v", out.Info)
	}
	for _, r := range e.fake.requests() {
		if r.path == "/json/"+captureUUID+"/status" && r.query != "with_error=1" {
			t.Errorf("status query = %q", r.query)
		}
	}
}

func TestSubmitWaitTimesOut(t *testing.T) {
	e := start(t, submitRoutes(statusOngoing), "", Options{})
	var out submitResult
	decode(t, e.call(t, "lk_submit", map[string]any{"url": "https://example.com/", "wait": true, "wait_timeout": 1}), &out)
	bound := 1000/250 + 1
	if out.Outcome != "timed_out" || *out.StatusCode != 2 || out.Polls != bound || out.Info != nil {
		t.Errorf("submit = %+v", out)
	}
	if n := count(e, "/json/"+captureUUID+"/status"); n != bound {
		t.Errorf("%d polls, bound %d", n, bound)
	}
	if n := count(e, "/json/"+captureUUID+"/info"); n != 0 {
		t.Errorf("info fetched for an unfinished capture")
	}
}

func TestSubmitWaitStopsOnPersistentUnknown(t *testing.T) {
	e := start(t, submitRoutes(statusUnknown), "", Options{})
	res := e.call(t, "lk_submit", map[string]any{"url": "https://example.com/", "wait": true})
	if !res.IsError || !strings.Contains(text(res), captureUUID) || !strings.Contains(text(res), "unknown") {
		t.Errorf("submit = %s", text(res))
	}
	if n := count(e, "/json/"+captureUUID+"/status"); n != 3 {
		t.Errorf("%d polls, want 3", n)
	}
}

func TestSubmitWaitReportsTheCaptureError(t *testing.T) {
	e := start(t, submitRoutes(`{"status_code": 1, "error": "net::ERR_NAME_NOT_RESOLVED"}`), "", Options{})
	var out submitResult
	decode(t, e.call(t, "lk_submit", map[string]any{"url": "https://example.com/", "wait": true}), &out)
	if out.Outcome != "done" || out.CaptureError != "net::ERR_NAME_NOT_RESOLVED" {
		t.Errorf("submit = %+v", out)
	}
}

func TestSubmitDocumentPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lure.html")
	html := []byte("<html><body>lure</body></html>")
	if err := os.WriteFile(path, html, 0o600); err != nil {
		t.Fatal(err)
	}
	e := start(t, submitRoutes(statusDone), "", Options{})
	var out submitResult
	decode(t, e.call(t, "lk_submit", map[string]any{"document_path": path}), &out)
	body := submitBody(t, e)
	if body["document"] != base64.StdEncoding.EncodeToString(html) || body["document_name"] != "lure.html" {
		t.Errorf("body = %v", body)
	}
	if _, ok := body["url"]; ok {
		t.Errorf("url sent with a document")
	}
}

func TestSubmitRejectsBadInputBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	for _, args := range []map[string]any{
		{},
		{"url": "https://example.com/", "document": "eA==", "document_name": "x.html"},
		{"url": "https://example.com/", "document_path": "/etc/hosts"},
		{"document_path": filepath.Join(t.TempDir(), "missing.html")},
		{"document": "eA=="},
		{"url": "https://example.com/", "wait": true, "wait_timeout": -1},
		{"url": "https://example.com/", "wait": true, "wait_timeout": 3601},
		{"url": "https://example.com/", "browser_name": "lynx"},
		{"url": "https://example.com/", "proxy": "nope"},
	} {
		if res := e.call(t, "lk_submit", args); !res.IsError {
			t.Errorf("%v was accepted", args)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestSubmitNeverReturnsTheProxy(t *testing.T) {
	proxy := "http://analyst:Sup3rS3cret@proxy.internal:3128"
	e := start(t, submitRoutes(statusDone), "", Options{})
	res := e.call(t, "lk_submit", map[string]any{"url": "https://example.com/", "proxy": proxy, "wait": true})
	if res.IsError {
		t.Fatal(text(res))
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "Sup3rS3cret") || strings.Contains(string(b), "proxy.internal") {
		t.Errorf("the proxy is in the result: %s", b)
	}
	if submitBody(t, e)["proxy"] != proxy {
		t.Errorf("the proxy was not sent to Lookyloo")
	}

	echo := `{"message": "Unable to validate capture settings.", "details": [{"input": "` + proxy + `"}]}`
	e = start(t, map[string]reply{"POST /submit": {status: http.StatusBadRequest, body: echo}}, "", Options{})
	res = e.call(t, "lk_submit", map[string]any{"url": "https://example.com/", "proxy": proxy})
	if !res.IsError || strings.Contains(text(res), "Sup3rS3cret") {
		t.Errorf("error = %s", text(res))
	}
}

func TestTriggerModules(t *testing.T) {
	path := "/json/" + captureUUID + "/trigger_modules"
	e := start(t, map[string]reply{"POST " + path: {body: `{"VirusTotal": "Module not enabled."}`}}, "", Options{})
	res := e.call(t, "lk_trigger_modules", map[string]any{"capture_uuid": captureUUID, "force": true})
	if res.IsError || !strings.Contains(text(res), "VirusTotal") {
		t.Errorf("trigger = %s", text(res))
	}
	if b := string(e.fake.requests()[0].body); b != `{"force":true}` {
		t.Errorf("body = %s", b)
	}
}

func TestTriggerModulesUnknownAndInvalid(t *testing.T) {
	path := "/json/" + unknownUUID + "/trigger_modules"
	e := start(t, map[string]reply{"POST " + path: {status: http.StatusInternalServerError, fixture: "error_stats_unknown.json"}}, "", Options{})
	if res := e.call(t, "lk_trigger_modules", map[string]any{"capture_uuid": unknownUUID}); !res.IsError || !strings.Contains(text(res), "lk_capture_status") {
		t.Errorf("trigger = %s", text(res))
	}
	if res := e.call(t, "lk_trigger_modules", map[string]any{"capture_uuid": "../x"}); !res.IsError {
		t.Errorf("an invalid UUID was accepted")
	}
	if n := len(e.fake.requests()); n != 1 {
		t.Errorf("%d HTTP requests, want 1", n)
	}
}
