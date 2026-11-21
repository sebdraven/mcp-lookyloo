package lookyloo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const unknownUUID = "00000000-0000-4000-8000-000000000000"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

func serveFixture(t *testing.T, status int, name string) *httptest.Server {
	t.Helper()
	body := fixture(t, name)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func noCallServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the server was called: %s %s", r.Method, r.URL)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNewDefaultsAndTrimsBaseURL(t *testing.T) {
	if got := New("").BaseURL(); got != DefaultBaseURL {
		t.Errorf("default base URL = %q", got)
	}
	if got := New(" http://lookyloo.example:5100/ ").BaseURL(); got != "http://lookyloo.example:5100" {
		t.Errorf("base URL = %q", got)
	}
}

func TestRequestHeaders(t *testing.T) {
	var ua, auth, ctype, fields string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua, auth = r.Header.Get("User-Agent"), r.Header.Get("Authorization")
		ctype, fields = r.Header.Get("Content-Type"), r.Header.Get("X-Fields")
		w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	c := New(srv.URL, WithVersion("1.2.3"), WithTokenSource(StaticToken("TOKEN")))
	_, err := c.doJSON(context.Background(), request{
		method: http.MethodPost,
		path:   "/json/x",
		body:   map[string]int{"a": 1},
		header: http.Header{"X-Fields": {"root_url"}},
		auth:   authRequired,
	})
	if err != nil {
		t.Fatalf("doJSON: %v", err)
	}
	if ua != "mcp-lookyloo/1.2.3" {
		t.Errorf("User-Agent = %q", ua)
	}
	if auth != "TOKEN" {
		t.Errorf("Authorization = %q", auth)
	}
	if ctype != "application/json" {
		t.Errorf("Content-Type = %q", ctype)
	}
	if fields != "root_url" {
		t.Errorf("X-Fields = %q", fields)
	}
}

func TestAPIErrorKeepsStatusAndFirst512Bytes(t *testing.T) {
	long := strings.Repeat("x", 2000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(long))
	}))
	defer srv.Close()

	_, err := New(srv.URL).doJSON(context.Background(), request{method: http.MethodGet, path: "/json/stats"})
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if ae.StatusCode != http.StatusBadGateway || ae.Method != http.MethodGet || ae.Path != "/json/stats" {
		t.Errorf("APIError = %+v", ae)
	}
	if len(ae.Body) != 512 {
		t.Errorf("body kept %d bytes, want 512", len(ae.Body))
	}
	if !strings.Contains(err.Error(), "HTTP 502") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestRecordedHTTPErrors(t *testing.T) {
	cases := []struct {
		fixture string
		status  int
		path    string
		want    string
	}{
		{"error_hostnames_unknown.json", http.StatusBadRequest, "/json/" + unknownUUID + "/hostnames", "UUID missing in cache"},
		{"error_stats_unknown.json", http.StatusInternalServerError, "/json/" + unknownUUID + "/stats", "Internal Server Error"},
		{"error_user_config_noauth.json", http.StatusForbidden, "/json/get_user_config", "Authentication required"},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			srv := serveFixture(t, tc.status, tc.fixture)
			_, err := New(srv.URL).doJSON(context.Background(), request{method: http.MethodGet, path: tc.path})
			var ae *APIError
			if !errors.As(err, &ae) || ae.StatusCode != tc.status {
				t.Fatalf("err = %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q does not carry %q", err.Error(), tc.want)
			}
		})
	}
}

func TestErrorEnvelopeWithStatus200(t *testing.T) {
	srv := serveFixture(t, http.StatusOK, "error_info_unknown.json")
	_, err := New(srv.URL).doJSON(context.Background(), request{method: http.MethodGet, path: "/json/" + unknownUUID + "/info"})
	var le *LookylooError
	if !errors.As(err, &le) {
		t.Fatalf("err = %v, want *LookylooError", err)
	}
	if le.Message != "Unable to find UUID "+unknownUUID+" in the cache." {
		t.Errorf("message = %q", le.Message)
	}
}

func TestErrorEnvelopeOnlyForBareErrorObjects(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`{"error": "x"}`, true},
		{`{"error": "x", "details": {"a": -1}}`, true},
		{`{"error": {"message": "nested"}}`, true},
		{`{"status_code": 1, "error": "net::ERR_x"}`, false},
		{`{"response": {"hostnames": []}}`, false},
		{`["error"]`, false},
		{`{"weeks": [], "years": [], "error": false}`, false},
	}
	for _, tc := range cases {
		if got := errorEnvelope([]byte(tc.body)) != nil; got != tc.want {
			t.Errorf("errorEnvelope(%s) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

func TestStatusFixtureIsNotAnError(t *testing.T) {
	srv := serveFixture(t, http.StatusOK, "status_unknown.json")
	raw, err := New(srv.URL).doJSON(context.Background(), request{method: http.MethodGet, path: "/json/" + unknownUUID + "/status"})
	if err != nil {
		t.Fatalf("doJSON: %v", err)
	}
	var st struct {
		StatusCode int `json:"status_code"`
	}
	if err := json.Unmarshal(raw, &st); err != nil || st.StatusCode != -1 {
		t.Errorf("status = %s (%v)", raw, err)
	}
}

func TestNonJSONResponseIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>proxy error</html>"))
	}))
	defer srv.Close()
	if _, err := New(srv.URL).doJSON(context.Background(), request{method: http.MethodGet, path: "/json/stats"}); err == nil {
		t.Fatal("HTML was accepted as JSON")
	}
}

func TestNormaliseUUID(t *testing.T) {
	good := []struct{ in, want string }{
		{unknownUUID, unknownUUID},
		{" 3BDC0267-4C13-4EE1-8014-DCCA6FB20C84 ", "3bdc0267-4c13-4ee1-8014-dcca6fb20c84"},
		{"3bdc0267-4c13-4ee1-8014-dcca6fb20c84", "3bdc0267-4c13-4ee1-8014-dcca6fb20c84"},
	}
	for _, tc := range good {
		got, err := NormaliseUUID(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("NormaliseUUID(%q) = %q, %v", tc.in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "../json/stats", "3bdc0267-4c13-4ee1-8014-dcca6fb20c8", "3bdc0267-4c13-4ee1-8014-dcca6fb20c84/info"} {
		if _, err := NormaliseUUID(bad); err == nil {
			t.Errorf("NormaliseUUID(%q) was accepted", bad)
		}
	}
}
