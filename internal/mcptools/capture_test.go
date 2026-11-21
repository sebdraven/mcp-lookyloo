package mcptools

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

type toolCase struct {
	tool    string
	path    string
	fixture string
	want    string
}

var rawCaptureCases = []toolCase{
	{"lk_capture_info", "/info", "capture_info.json", `"title": "Example Domain"`},
	{"lk_capture_stats", "/stats", "capture_stats.json", `"total_redirects": 1`},
	{"lk_capture_redirects", "/redirects", "capture_redirects.json", `"redirects": ["https://example.com/"]`},
	{"lk_capture_cookies", "/cookies", "capture_cookies.json", `"value": "REDACTED"`},
	{"lk_capture_comparables", "/comparables", "capture_comparables.json", `"final_status_code": 200`},
	{"lk_capture_modules", "/modules", "capture_modules.json", `{}`},
	{"lk_capture_misp_export", "/misp_export", "capture_misp_export.json", `"Attribute"`},
}

var unknownCaptureCases = []struct {
	tool    string
	path    string
	status  int
	fixture string
	want    string
}{
	{"lk_capture_info", "/info", http.StatusOK, "error_info_unknown.json", "Unable to find UUID " + unknownUUID},
	{"lk_capture_status", "/status", http.StatusOK, "status_unknown.json", `"status_code":-1`},
	{"lk_capture_stats", "/stats", http.StatusInternalServerError, "error_stats_unknown.json", "lk_capture_status"},
	{"lk_capture_redirects", "/redirects", http.StatusBadRequest, "error_hostnames_unknown.json", "UUID missing in cache"},
	{"lk_capture_urls", "/urls", http.StatusBadRequest, "error_hostnames_unknown.json", "UUID missing in cache"},
	{"lk_capture_hostnames", "/hostnames", http.StatusBadRequest, "error_hostnames_unknown.json", "UUID missing in cache"},
	{"lk_capture_hashes", "/hashes", http.StatusBadRequest, "error_hostnames_unknown.json", "UUID missing in cache"},
	{"lk_capture_cookies", "/cookies", http.StatusInternalServerError, "error_cookies_none.json", "lk_capture_status"},
	{"lk_capture_comparables", "/comparables", http.StatusInternalServerError, "error_stats_unknown.json", "HTTP 500"},
	{"lk_capture_modules", "/modules", http.StatusOK, "unknown_modules.json", "{}"},
	{"lk_capture_misp_export", "/misp_export", http.StatusOK, "unknown_misp_export.json", "UUID missing in cache, try again later."},
}

var captureTools = []string{
	"lk_capture_info", "lk_capture_status", "lk_capture_stats", "lk_capture_redirects", "lk_capture_urls",
	"lk_capture_hostnames", "lk_capture_hashes", "lk_capture_cookies", "lk_capture_comparables",
	"lk_capture_modules", "lk_capture_misp_export",
}

func TestRawCaptureToolsNominal(t *testing.T) {
	for _, tc := range rawCaptureCases {
		t.Run(tc.tool, func(t *testing.T) {
			e := start(t, map[string]reply{"GET /json/" + captureUUID + tc.path: {fixture: tc.fixture}}, "", Options{})
			res := e.call(t, tc.tool, map[string]any{"capture_uuid": captureUUID})
			if res.IsError {
				t.Fatalf("tool error: %s", text(res))
			}
			if got := text(res); !strings.Contains(got, tc.want) {
				t.Errorf("result does not contain %s:\n%.400s", tc.want, got)
			}
			if res.StructuredContent != nil {
				t.Errorf("raw tools must not set structured content")
			}
			reqs := e.fake.requests()
			if len(reqs) != 1 || reqs[0].method != http.MethodGet || len(reqs[0].body) != 0 {
				t.Errorf("requests = %+v", reqs)
			}
			if h := reqs[0].header.Get("Authorization"); h != "" {
				t.Errorf("an anonymous call sent Authorization %q", h)
			}
		})
	}
}

func TestCaptureToolsUnknownUUID(t *testing.T) {
	for _, tc := range unknownCaptureCases {
		t.Run(tc.tool, func(t *testing.T) {
			e := start(t, map[string]reply{"GET /json/" + unknownUUID + tc.path: {status: tc.status, fixture: tc.fixture}}, "", Options{})
			res := e.call(t, tc.tool, map[string]any{"capture_uuid": unknownUUID})
			got := text(res)
			if !strings.Contains(got, tc.want) {
				t.Errorf("result does not contain %q:\n%.400s", tc.want, got)
			}
			// status and modules report an unknown UUID as data, not as an error.
			wantErr := tc.tool != "lk_capture_status" && tc.tool != "lk_capture_modules"
			if res.IsError != wantErr {
				t.Errorf("IsError = %v, want %v: %s", res.IsError, wantErr, got)
			}
		})
	}
}

func TestCaptureToolsRejectInvalidUUIDBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	for _, tool := range captureTools {
		for _, bad := range []string{"", "not-a-uuid", "../../admin/rebuild_all", captureUUID + "/x"} {
			res := e.call(t, tool, map[string]any{"capture_uuid": bad})
			if !res.IsError {
				t.Errorf("%s(%q) was accepted: %s", tool, bad, text(res))
			}
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests for invalid UUIDs", n)
	}
}

func TestCaptureStatus(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/" + captureUUID + "/status": {fixture: "capture_status.json"}}, "", Options{})
	var st struct {
		StatusCode int `json:"status_code"`
	}
	decode(t, e.call(t, "lk_capture_status", map[string]any{"capture_uuid": captureUUID, "with_error": true}), &st)
	if st.StatusCode != 1 {
		t.Errorf("status_code = %d", st.StatusCode)
	}
	if q := e.fake.requests()[0].query; q != "with_error=1" {
		t.Errorf("query = %q", q)
	}

	decode(t, e.call(t, "lk_capture_status", map[string]any{"capture_uuid": captureUUID}), &st)
	if q := e.fake.requests()[1].query; q != "" {
		t.Errorf("with_error=false sent %q; Lookyloo treats any value as true", q)
	}
}

func TestCaptureStatusCarriesTheError(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/" + captureUUID + "/status": {body: `{"status_code": 1, "error": "net::ERR_NAME_NOT_RESOLVED"}`}}, "", Options{})
	var st struct {
		StatusCode int    `json:"status_code"`
		Error      string `json:"error"`
	}
	decode(t, e.call(t, "lk_capture_status", map[string]any{"capture_uuid": captureUUID, "with_error": true}), &st)
	if st.StatusCode != 1 || st.Error != "net::ERR_NAME_NOT_RESOLVED" {
		t.Errorf("status = %+v", st)
	}
}

type listResult struct {
	CaptureUUID string   `json:"capture_uuid"`
	Items       []string `json:"items"`
	Total       int      `json:"total"`
	Offset      int      `json:"offset"`
	Count       int      `json:"count"`
	HasMore     bool     `json:"has_more"`
	NextOffset  int      `json:"next_offset"`
}

func TestCaptureURLsAndHostnames(t *testing.T) {
	e := start(t, map[string]reply{
		"GET /json/" + captureUUID + "/urls":      {fixture: "capture_urls.json"},
		"GET /json/" + captureUUID + "/hostnames": {fixture: "capture_hostnames.json"},
	}, "", Options{})

	var urls listResult
	decode(t, e.call(t, "lk_capture_urls", map[string]any{"capture_uuid": strings.ToUpper(captureUUID)}), &urls)
	want := []string{"https://example.com/", "https://example.com/s.js"}
	if !slices.Equal(urls.Items, want) || urls.Total != 2 || urls.Count != 2 || urls.HasMore {
		t.Errorf("urls = %+v", urls)
	}
	if urls.CaptureUUID != captureUUID {
		t.Errorf("capture_uuid = %q, want the normalised UUID", urls.CaptureUUID)
	}

	var hosts listResult
	decode(t, e.call(t, "lk_capture_hostnames", map[string]any{"capture_uuid": captureUUID}), &hosts)
	if !slices.Equal(hosts.Items, []string{"example.com"}) {
		t.Errorf("hostnames = %+v", hosts)
	}
}

func TestCaptureURLsPagination(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/" + captureUUID + "/urls": {fixture: "capture_urls.json"}}, "", Options{})

	var p1 listResult
	decode(t, e.call(t, "lk_capture_urls", map[string]any{"capture_uuid": captureUUID, "limit": 1}), &p1)
	if !slices.Equal(p1.Items, []string{"https://example.com/"}) || !p1.HasMore || p1.NextOffset != 1 || p1.Total != 2 {
		t.Errorf("page 1 = %+v", p1)
	}
	var p2 listResult
	decode(t, e.call(t, "lk_capture_urls", map[string]any{"capture_uuid": captureUUID, "limit": 1, "offset": p1.NextOffset}), &p2)
	if !slices.Equal(p2.Items, []string{"https://example.com/s.js"}) || p2.HasMore || p2.NextOffset != 0 {
		t.Errorf("page 2 = %+v", p2)
	}
	var past listResult
	decode(t, e.call(t, "lk_capture_urls", map[string]any{"capture_uuid": captureUUID, "offset": 10}), &past)
	if past.Count != 0 || past.Items == nil || past.HasMore {
		t.Errorf("past the end = %+v", past)
	}
}

func TestPaginationRejectsBadBoundsBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	for _, tool := range []string{"lk_capture_urls", "lk_capture_hostnames", "lk_capture_hashes"} {
		for _, args := range []map[string]any{
			{"capture_uuid": captureUUID, "limit": -1},
			{"capture_uuid": captureUUID, "limit": 10001},
			{"capture_uuid": captureUUID, "offset": -5},
		} {
			if res := e.call(t, tool, args); !res.IsError {
				t.Errorf("%s(%v) was accepted", tool, args)
			}
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests for invalid bounds", n)
	}
}

type hashesResult struct {
	Algorithm      string              `json:"algorithm"`
	Hashes         []string            `json:"hashes"`
	HashesWithURLs map[string][]string `json:"hashes_with_urls"`
	Total          int                 `json:"total"`
	HasMore        bool                `json:"has_more"`
}

func TestCaptureHashesDefaultsToCompleteSHA512(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/" + captureUUID + "/hashes": {fixture: "capture_hashes.json"}}, "", Options{})
	var h hashesResult
	decode(t, e.call(t, "lk_capture_hashes", map[string]any{"capture_uuid": captureUUID}), &h)
	if h.Algorithm != "sha512" || h.Total != 3 || len(h.Hashes) != 3 || h.HashesWithURLs != nil {
		t.Fatalf("hashes = %+v", h)
	}
	for _, x := range h.Hashes {
		if len(x) != 128 {
			t.Errorf("hash %q is not a complete sha512", x)
		}
	}
	if !slices.IsSorted(h.Hashes) {
		t.Errorf("hashes are not sorted: %v", h.Hashes)
	}
	if q := e.fake.requests()[0].query; q != "algorithm=sha512" {
		t.Errorf("query = %q", q)
	}
}

func TestCaptureHashesWithURLs(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/" + captureUUID + "/hashes": {fixture: "capture_hashes_sha256_with_urls.json"}}, "", Options{})
	var h hashesResult
	decode(t, e.call(t, "lk_capture_hashes", map[string]any{
		"capture_uuid": captureUUID, "algorithm": "sha256", "hashes_only": false, "limit": 2,
	}), &h)
	if len(h.Hashes) != 2 || !h.HasMore || h.Total != 3 || len(h.HashesWithURLs) != 2 {
		t.Fatalf("hashes = %+v", h)
	}
	root := "25ddf2c883e0d1958ea971d279a7e4f0fd446724ee3db7db19dadabd4a62e484"
	if !slices.Equal(h.HashesWithURLs[root], []string{"https://example.com/"}) {
		t.Errorf("urls of %s = %v", root, h.HashesWithURLs[root])
	}
	if q := e.fake.requests()[0].query; q != "algorithm=sha256&hashes_only=0" {
		t.Errorf("query = %q", q)
	}
}

func TestCaptureHashesRejectsUnknownAlgorithmBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	for _, algo := range []string{"crc32", "shake_128", "sha512; rm"} {
		if res := e.call(t, "lk_capture_hashes", map[string]any{"capture_uuid": captureUUID, "algorithm": algo}); !res.IsError {
			t.Errorf("algorithm %q was accepted", algo)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestCaptureComparablesFieldsMask(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/" + captureUUID + "/comparables": {fixture: "capture_comparables.json"}}, "", Options{})
	res := e.call(t, "lk_capture_comparables", map[string]any{"capture_uuid": captureUUID, "fields": "root_url,redirects{length}"})
	if res.IsError {
		t.Fatal(text(res))
	}
	if got := e.fake.requests()[0].header.Get("X-Fields"); got != "root_url,redirects{length}" {
		t.Errorf("X-Fields = %q", got)
	}

	for _, bad := range []string{"root_url\r\nAuthorization: x", "a;b", "<script>"} {
		if res := e.call(t, "lk_capture_comparables", map[string]any{"capture_uuid": captureUUID, "fields": bad}); !res.IsError {
			t.Errorf("fields %q was accepted", bad)
		}
	}
	if n := len(e.fake.requests()); n != 1 {
		t.Errorf("%d HTTP requests, want 1", n)
	}
}
