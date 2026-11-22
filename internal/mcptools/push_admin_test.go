package mcptools

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var withPush = Options{AllowPush: true}

func TestCaptureReportSendsTheJSONBody(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/" + captureUUID + "/report": {body: "true"}}, "", withPush)
	res := e.call(t, "lk_capture_report", map[string]any{"capture_uuid": captureUUID, "email": "analyst@example.org", "comment": "phishing kit"})
	if res.IsError || text(res) != "true" {
		t.Fatalf("report = %s", text(res))
	}
	r := e.fake.requests()[0]
	if r.query != "" || string(r.body) != `{"email":"analyst@example.org","comment":"phishing kit"}` {
		t.Errorf("query %q, body %s", r.query, r.body)
	}
}

func TestCaptureReportErrorsAndInvalid(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/" + captureUUID + "/report": {body: `{"error": "Unable to send mail: mail notification disabled"}`}}, "", withPush)
	if res := e.call(t, "lk_capture_report", map[string]any{"capture_uuid": captureUUID}); !res.IsError || !strings.Contains(text(res), "mail notification disabled") {
		t.Errorf("report = %s", text(res))
	}
	for _, args := range []map[string]any{{"capture_uuid": "x"}, {"capture_uuid": captureUUID, "email": "a@b.c, d@e.f"}} {
		if res := e.call(t, "lk_capture_report", args); !res.IsError {
			t.Errorf("%v was accepted", args)
		}
	}
	if n := len(e.fake.requests()); n != 1 {
		t.Errorf("%d HTTP requests, want 1", n)
	}
}

func TestMISPPush(t *testing.T) {
	events := `[{"Event": {"uuid": "25026d4d-f849-408e-bb5e-b0e33221c5f1", "info": "Lookyloo Capture"}}]`
	e := start(t, map[string]reply{
		"POST /json/" + captureUUID + "/misp_push":         {body: events},
		"POST /json/" + captureUUID + "/misp_push/misp-ce": {body: events},
	}, "TOKEN", withPush)

	res := e.call(t, "lk_misp_push", map[string]any{"capture_uuid": captureUUID, "allow_duplicates": true})
	if res.IsError || !strings.Contains(text(res), "Lookyloo Capture") {
		t.Fatalf("push = %s", text(res))
	}
	r := e.fake.requests()[0]
	if r.header.Get("Authorization") != "TOKEN" || string(r.body) != `{"allow_duplicates":1,"with_parents":0}` {
		t.Errorf("auth %q, body %s", r.header.Get("Authorization"), r.body)
	}

	e.call(t, "lk_misp_push", map[string]any{"capture_uuid": captureUUID, "instance_name": "misp-ce", "with_parents": true})
	if r := e.fake.requests()[1]; r.path != "/json/"+captureUUID+"/misp_push/misp-ce" || string(r.body) != `{"allow_duplicates":0,"with_parents":1}` {
		t.Errorf("request %s %s", r.path, r.body)
	}
}

func TestMISPPushNeedsATokenAndValidInput(t *testing.T) {
	e := start(t, map[string]reply{}, "", withPush)
	if res := e.call(t, "lk_misp_push", map[string]any{"capture_uuid": captureUUID}); !res.IsError || !strings.Contains(text(res), "LOOKYLOO_API_KEY") {
		t.Errorf("push without token = %s", text(res))
	}
	e = start(t, map[string]reply{}, "TOKEN", withPush)
	for _, args := range []map[string]any{
		{"capture_uuid": "nope"},
		{"capture_uuid": captureUUID, "instance_name": "../admin"},
		{"capture_uuid": captureUUID, "instance_name": "a b"},
	} {
		if res := e.call(t, "lk_misp_push", args); !res.IsError {
			t.Errorf("%v was accepted", args)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestMISPPushReportsLookylooErrors(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/" + captureUUID + "/misp_push": {body: `{"error": "MISP module not available."}`}}, "TOKEN", withPush)
	if res := e.call(t, "lk_misp_push", map[string]any{"capture_uuid": captureUUID}); !res.IsError || !strings.Contains(text(res), "MISP module not available.") {
		t.Errorf("push = %s", text(res))
	}
}

func TestUploadFullCapture(t *testing.T) {
	dir := t.TempDir()
	zipBytes := readFixture(t, "capture_export.zip")
	if err := os.WriteFile(filepath.Join(dir, "export.zip"), zipBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	e := start(t, map[string]reply{"POST /json/upload": {body: `{"uuid": "` + unknownUUID + `", "messages": {"errors": [], "warnings": []}}`}}, "", Options{AllowPush: true, FilesRoot: mustRoot(t, dir)})

	var out struct {
		UUID     string         `json:"uuid"`
		Messages map[string]any `json:"messages"`
	}
	decode(t, e.call(t, "lk_upload_capture", map[string]any{"full_capture_path": "export.zip"}), &out)
	if out.UUID != unknownUUID || out.Messages == nil {
		t.Errorf("upload = %+v", out)
	}
	var body map[string]any
	if err := json.Unmarshal(e.fake.requests()[0].body, &body); err != nil {
		t.Fatal(err)
	}
	if body["listing"] != float64(0) || body["full_capture"] != base64.StdEncoding.EncodeToString(zipBytes) || len(body) != 2 {
		t.Errorf("body keys = %v", keys(body))
	}
}

func TestUploadHAR(t *testing.T) {
	dir := t.TempDir()
	har := filepath.Join(dir, "0.har")
	png := filepath.Join(dir, "0.png")
	if err := os.WriteFile(har, []byte(`{"log": {"entries": []}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(png, readFixture(t, "capture_screenshot.png"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := start(t, map[string]reply{"POST /json/upload": {body: `{"uuid": "` + captureUUID + `"}`}}, "", Options{AllowPush: true, FilesRoot: mustRoot(t, dir)})
	res := e.call(t, "lk_upload_capture", map[string]any{"har_file_path": har, "screenshot_path": png, "landing_page": "https://example.com/", "listing": true})
	if res.IsError {
		t.Fatal(text(res))
	}
	var body map[string]any
	if err := json.Unmarshal(e.fake.requests()[0].body, &body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"har_file", "screenshot_file", "landing_page"} {
		if body[k] == nil {
			t.Errorf("%s missing from %v", k, keys(body))
		}
	}
	if body["listing"] != float64(1) || body["full_capture"] != nil {
		t.Errorf("body keys = %v", keys(body))
	}
}

func TestUploadRejectsBadInputBeforeHTTP(t *testing.T) {
	dir := t.TempDir()
	notZip := filepath.Join(dir, "x.zip")
	if err := os.WriteFile(notZip, []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := start(t, map[string]reply{}, "", Options{AllowPush: true, FilesRoot: mustRoot(t, dir)})
	for _, args := range []map[string]any{
		{},
		{"full_capture": "UEsDBA==", "har_file": "e30="},
		{"full_capture_path": notZip},
		{"full_capture_path": filepath.Join(dir, "missing.zip")},
		{"full_capture": "not base64"},
		{"har_file": base64.StdEncoding.EncodeToString([]byte("<html>"))},
		{"full_capture": "UEsDBA==", "landing_page": "https://example.com/"},
		{"har_file": "e30=", "screenshot_path": notZip},
	} {
		if res := e.call(t, "lk_upload_capture", args); !res.IsError {
			t.Errorf("%v was accepted", args)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestUploadReportsLookylooErrors(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/upload": {status: http.StatusBadRequest, body: `{"error": "Invalid submission: missing HAR file"}`}}, "", withPush)
	if res := e.call(t, "lk_upload_capture", map[string]any{"full_capture": "UEsDBA=="}); !res.IsError || !strings.Contains(text(res), "missing HAR file") {
		t.Errorf("upload = %s", text(res))
	}
}

func TestAdminTools(t *testing.T) {
	cases := []struct {
		tool string
		path string
		args map[string]any
	}{
		{"lk_admin_hide", "/admin/" + captureUUID + "/hide", map[string]any{"capture_uuid": captureUUID}},
		{"lk_admin_rebuild", "/admin/" + captureUUID + "/rebuild", map[string]any{"capture_uuid": captureUUID}},
		{"lk_admin_remove", "/admin/" + captureUUID + "/remove", map[string]any{"capture_uuid": captureUUID}},
		{"lk_admin_rebuild_cache", "/admin/rebuild_all_cache", map[string]any{}},
		{"lk_admin_rebuild_all", "/admin/rebuild_all", map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			e := start(t, map[string]reply{"POST " + tc.path: {body: `{"info": "done"}`}}, "TOKEN", Options{AllowAdmin: true})
			if res := e.call(t, tc.tool, tc.args); res.IsError || !strings.Contains(text(res), "done") {
				t.Fatalf("%s = %s", tc.tool, text(res))
			}
			if r := e.fake.requests()[0]; r.header.Get("Authorization") != "TOKEN" || len(r.body) != 0 {
				t.Errorf("auth %q, body %s", r.header.Get("Authorization"), r.body)
			}

			e = start(t, map[string]reply{"POST " + tc.path: {status: http.StatusBadRequest, body: `{"error": "Unable to do it"}`}}, "TOKEN", Options{AllowAdmin: true})
			if res := e.call(t, tc.tool, tc.args); !res.IsError || !strings.Contains(text(res), "Unable to do it") {
				t.Errorf("%s error = %s", tc.tool, text(res))
			}

			e = start(t, map[string]reply{}, "", Options{AllowAdmin: true})
			if res := e.call(t, tc.tool, tc.args); !res.IsError || !strings.Contains(text(res), "LOOKYLOO_API_KEY") {
				t.Errorf("%s without token = %s", tc.tool, text(res))
			}
			if n := len(e.fake.requests()); n != 0 {
				t.Errorf("%d HTTP requests without a token", n)
			}
		})
	}
}

func TestAdminToolsRejectInvalidUUIDBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "TOKEN", Options{AllowAdmin: true})
	for _, tool := range []string{"lk_admin_hide", "lk_admin_rebuild", "lk_admin_remove"} {
		if res := e.call(t, tool, map[string]any{"capture_uuid": "../rebuild_all"}); !res.IsError {
			t.Errorf("%s accepted a path", tool)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestPushAndAdminToolsAreAbsentByDefault(t *testing.T) {
	e := start(t, map[string]reply{}, "TOKEN", Options{})
	for _, tool := range slices.Concat(pushTools, adminTools) {
		res, err := e.session.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"capture_uuid": captureUUID}})
		if err == nil && !res.IsError {
			t.Errorf("%s is callable without its flag", tool)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
