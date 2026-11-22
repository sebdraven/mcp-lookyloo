package mcptools

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

var searchTools = []string{
	"lk_url_info", "lk_hostname_info", "lk_hash_info", "lk_tld_captures",
	"lk_categories", "lk_recent_captures", "lk_compare_captures", "lk_takedown_info",
}

const rootSHA512 = "0777a36b4bec736adadc9da3b974f814056ee0a92e1df563cc2b939a282c4c75d7939b95854026d64f5866cdd02ab3ff8c6c2c1061b1a10e73f9a380fc0863fb"

type occurrencesResult struct {
	Count     int              `json:"count"`
	Truncated bool             `json:"truncated"`
	Captures  []map[string]any `json:"captures"`
}

func TestURLInfo(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/url_info": {fixture: "url_info.json"}}, "", Options{})
	var out occurrencesResult
	decode(t, e.call(t, "lk_url_info", map[string]any{"url": "https://example.com/"}), &out)
	if out.Count != 1 || out.Truncated || out.Captures[0]["capture_uuid"] != captureUUID {
		t.Fatalf("url_info = %+v", out)
	}
	if !strings.Contains(mustJSON(t, out.Captures[0]), rootSHA512) {
		t.Errorf("the complete sha512 of the body is missing: %v", out.Captures[0])
	}
	var body map[string]any
	if err := json.Unmarshal(e.fake.requests()[0].body, &body); err != nil {
		t.Fatal(err)
	}
	if body["url"] != "https://example.com/" || body["limit"] != float64(20) || body["cached_captures_only"] != true {
		t.Errorf("body = %v", body)
	}
}

func TestURLInfoAppliesLimit(t *testing.T) {
	two := `[{"capture_uuid": "` + captureUUID + `"}, {"capture_uuid": "` + unknownUUID + `"}]`
	e := start(t, map[string]reply{"POST /json/url_info": {body: two}}, "", Options{})
	var out occurrencesResult
	decode(t, e.call(t, "lk_url_info", map[string]any{"url": "https://example.com/", "limit": 1, "cached_captures_only": false}), &out)
	if out.Count != 1 || !out.Truncated {
		t.Errorf("url_info = %+v", out)
	}
	if !strings.Contains(string(e.fake.requests()[0].body), `"cached_captures_only":false`) {
		t.Errorf("body = %s", e.fake.requests()[0].body)
	}
}

func TestURLInfoNotSeen(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/url_info": {fixture: "url_info_none.json"}}, "", Options{})
	var out occurrencesResult
	decode(t, e.call(t, "lk_url_info", map[string]any{"url": "https://unseen.invalid/nothing"}), &out)
	if out.Count != 0 || out.Captures == nil {
		t.Errorf("url_info = %+v", out)
	}
}

func TestHostnameInfo(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/hostname_info": {fixture: "hostname_info_none.json"}}, "", Options{})
	var out occurrencesResult
	decode(t, e.call(t, "lk_hostname_info", map[string]any{"hostname": "example.com", "limit": 5}), &out)
	if out.Count != 0 {
		t.Errorf("hostname_info = %+v", out)
	}
	if b := string(e.fake.requests()[0].body); !strings.Contains(b, `"hostname":"example.com"`) || strings.Contains(b, `"url"`) {
		t.Errorf("body = %s", b)
	}
}

func TestOccurrenceToolsRejectInvalidInputBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"lk_url_info", map[string]any{"url": "  "}},
		{"lk_url_info", map[string]any{"url": "https://example.com/", "limit": -1}},
		{"lk_hostname_info", map[string]any{"hostname": "example.com/path"}},
		{"lk_hostname_info", map[string]any{"hostname": "a b"}},
		{"lk_hostname_info", map[string]any{"hostname": "example.com", "limit": 20000}},
	}
	for _, tc := range cases {
		if res := e.call(t, tc.tool, tc.args); !res.IsError {
			t.Errorf("%s(%v) was accepted", tc.tool, tc.args)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestHashInfo(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/hash_info/" + rootSHA512: {fixture: "hash_info_synthetic.json"}}, "", Options{})
	res := e.call(t, "lk_hash_info", map[string]any{"h": strings.ToUpper(rootSHA512)})
	if res.IsError || !strings.Contains(text(res), `"hash": "`+rootSHA512+`"`) {
		t.Errorf("hash_info = %s", text(res))
	}
}

func TestHashInfoUnknownAndBroken(t *testing.T) {
	for _, tc := range []struct {
		status  int
		fixture string
		want    string
	}{
		{http.StatusBadRequest, "hash_info_unknown.json", "Unknown Hash."},
		{http.StatusInternalServerError, "hash_info_error.json", "HTTP 500"},
	} {
		e := start(t, map[string]reply{"GET /json/hash_info/" + rootSHA512: {status: tc.status, fixture: tc.fixture}}, "", Options{})
		res := e.call(t, "lk_hash_info", map[string]any{"h": rootSHA512})
		if !res.IsError || !strings.Contains(text(res), tc.want) {
			t.Errorf("hash_info = %s", text(res))
		}
	}
}

func TestHashInfoRejectsIncompleteHashBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	sha256 := "25ddf2c883e0d1958ea971d279a7e4f0fd446724ee3db7db19dadabd4a62e484"
	for _, bad := range []string{"", sha256, rootSHA512[:127], rootSHA512 + "0", strings.Replace(rootSHA512, "0", "g", 1), "../stats"} {
		if res := e.call(t, "lk_hash_info", map[string]any{"h": bad}); !res.IsError {
			t.Errorf("hash %q was accepted", bad)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestTLDCaptures(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/tlds": {fixture: "tlds.json"}}, "", Options{})
	res := e.call(t, "lk_tld_captures", map[string]any{})
	if res.IsError || !strings.Contains(text(res), `"com"`) {
		t.Errorf("tlds = %.200s", text(res))
	}
	if q := e.fake.requests()[0].query; q != "" {
		t.Errorf("query = %q", q)
	}

	e = start(t, map[string]reply{"GET /json/tlds": {fixture: "tlds_com.json"}}, "", Options{})
	res = e.call(t, "lk_tld_captures", map[string]any{"tld": ".COM", "oldest_capture": "1795000000", "most_recent_capture": "1795300000.5"})
	if res.IsError || !strings.Contains(text(res), captureUUID) {
		t.Errorf("tlds com = %.200s", text(res))
	}
	if q := e.fake.requests()[0].query; q != "most_recent_capture=1795300000.5&oldest_capture=1795000000&tld=com" {
		t.Errorf("query = %q", q)
	}

	e = start(t, map[string]reply{"GET /json/tlds": {fixture: "tlds_invalid_urls.json"}}, "", Options{})
	res = e.call(t, "lk_tld_captures", map[string]any{"tld": "invalid", "urls_only": true})
	if res.IsError || !strings.Contains(text(res), "chrome-extension://invalid/") {
		t.Errorf("tlds urls = %s", text(res))
	}
	if q := e.fake.requests()[0].query; q != "tld=invalid&urls_only=1" {
		t.Errorf("query = %q", q)
	}
}

func TestTLDCapturesRejectsInvalidInputBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	for _, args := range []map[string]any{
		{"tld": "co m"},
		{"tld": "com/../x"},
		{"tld": "com", "oldest_capture": "yesterday"},
		{"tld": "com", "most_recent_capture": "-1"},
		{"tld": "com", "most_recent_capture": "NaN"},
		{"urls_only": true},
	} {
		if res := e.call(t, "lk_tld_captures", args); !res.IsError {
			t.Errorf("%v was accepted", args)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestCategories(t *testing.T) {
	e := start(t, map[string]reply{
		"GET /json/categories":          {fixture: "categories.json"},
		"GET /json/categories/phishing": {fixture: "category_phishing.json"},
	}, "", Options{})
	if res := e.call(t, "lk_categories", map[string]any{}); res.IsError || text(res) != "{}" {
		t.Errorf("categories = %s", text(res))
	}
	if res := e.call(t, "lk_categories", map[string]any{"category": "phishing"}); res.IsError || text(res) != "[]" {
		t.Errorf("category = %s", text(res))
	}
	for _, bad := range []string{"../admin", "a b", "x?y"} {
		if res := e.call(t, "lk_categories", map[string]any{"category": bad}); !res.IsError {
			t.Errorf("category %q was accepted", bad)
		}
	}
	if n := len(e.fake.requests()); n != 2 {
		t.Errorf("%d HTTP requests, want 2", n)
	}
}

func TestCategoriesHTTPError(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/categories/nope": {status: http.StatusNotFound, body: `{"message": "not found"}`}}, "", Options{})
	if res := e.call(t, "lk_categories", map[string]any{"category": "nope"}); !res.IsError || !strings.Contains(text(res), "HTTP 404") {
		t.Errorf("category = %s", text(res))
	}
}

type recentResult struct {
	Captures   []string `json:"captures"`
	Total      int      `json:"total"`
	HasMore    bool     `json:"has_more"`
	NextOffset int      `json:"next_offset"`
}

func TestRecentCaptures(t *testing.T) {
	e := start(t, map[string]reply{
		"GET /json/recent_captures":            {fixture: "recent_captures.json"},
		"GET /json/recent_captures/1795285600": {fixture: "recent_captures_since.json"},
	}, "", Options{})

	var p1 recentResult
	decode(t, e.call(t, "lk_recent_captures", map[string]any{"limit": 2}), &p1)
	if len(p1.Captures) != 2 || p1.Captures[0] != captureUUID || !p1.HasMore || p1.NextOffset != 2 || p1.Total != 5 {
		t.Errorf("page 1 = %+v", p1)
	}

	var since recentResult
	decode(t, e.call(t, "lk_recent_captures", map[string]any{"timestamp": "1795285600"}), &since)
	if !slices.Equal(since.Captures, []string{captureUUID}) || since.HasMore {
		t.Errorf("since = %+v", since)
	}

	for _, args := range []map[string]any{{"timestamp": "../stats"}, {"timestamp": "1e400"}, {"limit": -2}, {"offset": -1}} {
		if res := e.call(t, "lk_recent_captures", args); !res.IsError {
			t.Errorf("%v was accepted", args)
		}
	}
	if n := len(e.fake.requests()); n != 2 {
		t.Errorf("%d HTTP requests, want 2", n)
	}
}

func TestRecentCapturesHTTPError(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/recent_captures": {status: http.StatusInternalServerError, fixture: "error_stats_unknown.json"}}, "", Options{})
	if res := e.call(t, "lk_recent_captures", map[string]any{}); !res.IsError || !strings.Contains(text(res), "HTTP 500") {
		t.Errorf("recent = %s", text(res))
	}
}

func TestCompareCaptures(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/compare_captures": {fixture: "compare_same.json"}}, "", Options{})
	res := e.call(t, "lk_compare_captures", map[string]any{
		"capture_left": captureUUID, "capture_right": strings.ToUpper(captureUUID),
		"ressources_ignore_domains": []string{"cdn.example.net"},
	})
	if res.IsError || !strings.Contains(text(res), `"different": false`) {
		t.Fatalf("compare = %s", text(res))
	}
	var body struct {
		Left     string `json:"capture_left"`
		Right    string `json:"capture_right"`
		Settings struct {
			Domains []string `json:"ressources_ignore_domains"`
			Regexes []string `json:"ressources_ignore_regexes"`
		} `json:"compare_settings"`
	}
	if err := json.Unmarshal(e.fake.requests()[0].body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Left != captureUUID || body.Right != captureUUID || !slices.Equal(body.Settings.Domains, []string{"cdn.example.net"}) || body.Settings.Regexes != nil {
		t.Errorf("body = %+v", body)
	}
}

func TestCompareCapturesUnknown(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/compare_captures": {fixture: "compare_unknown.json"}}, "", Options{})
	res := e.call(t, "lk_compare_captures", map[string]any{"capture_left": captureUUID, "capture_right": unknownUUID})
	if !res.IsError || !strings.Contains(text(res), "Unable to find UUID "+unknownUUID) || !strings.Contains(text(res), `"`+unknownUUID+`": -1`) {
		t.Errorf("compare = %s", text(res))
	}
}

func TestCompareCapturesWithoutSettingsAndInvalid(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/compare_captures": {fixture: "compare_same.json"}}, "", Options{})
	e.call(t, "lk_compare_captures", map[string]any{"capture_left": captureUUID, "capture_right": captureUUID})
	if b := string(e.fake.requests()[0].body); strings.Contains(b, "compare_settings") {
		t.Errorf("empty settings were sent: %s", b)
	}
	for _, args := range []map[string]any{
		{"capture_left": "x", "capture_right": captureUUID},
		{"capture_left": captureUUID, "capture_right": ""},
	} {
		if res := e.call(t, "lk_compare_captures", args); !res.IsError {
			t.Errorf("%v was accepted", args)
		}
	}
	if n := len(e.fake.requests()); n != 1 {
		t.Errorf("%d HTTP requests, want 1", n)
	}
}

func TestTakedownInfo(t *testing.T) {
	contacts := `[{"hostname": "example.com", "contacts": ["abuse@example.net"]}]`
	e := start(t, map[string]reply{"POST /json/takedown": {body: contacts}}, "", Options{})
	res := e.call(t, "lk_takedown_info", map[string]any{"capture_uuid": captureUUID, "filter": true})
	if res.IsError || !strings.Contains(text(res), "abuse@example.net") {
		t.Errorf("takedown = %s", text(res))
	}
	if b := string(e.fake.requests()[0].body); b != `{"capture_uuid":"`+captureUUID+`","filter":true}` {
		t.Errorf("body = %s", b)
	}
}

func TestTakedownInfoUnavailableAndInvalid(t *testing.T) {
	e := start(t, map[string]reply{"POST /json/takedown": {fixture: "takedown_unavailable.json"}}, "", Options{})
	res := e.call(t, "lk_takedown_info", map[string]any{"capture_uuid": captureUUID})
	if !res.IsError || !strings.Contains(text(res), "UWhois not available") {
		t.Errorf("takedown = %s", text(res))
	}
	if res := e.call(t, "lk_takedown_info", map[string]any{"capture_uuid": "nope"}); !res.IsError {
		t.Errorf("an invalid UUID was accepted")
	}
	if n := len(e.fake.requests()); n != 1 {
		t.Errorf("%d HTTP requests, want 1", n)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
