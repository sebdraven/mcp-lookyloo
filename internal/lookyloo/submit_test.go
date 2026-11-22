package lookyloo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testCapture = "a222e170-f406-4550-ac25-81bccd02c875"

// statusSequence answers /status with the given codes in order, repeating the last one.
type statusSequence struct {
	mu    sync.Mutex
	codes []int
	polls int
}

func (s *statusSequence) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := s.codes[min(s.polls, len(s.codes)-1)]
	s.polls++
	fmt.Fprintf(w, `{"status_code": %d}`, code)
}

func (s *statusSequence) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.polls
}

func waitClient(t *testing.T, codes ...int) (*Client, *statusSequence, *int) {
	t.Helper()
	seq := &statusSequence{codes: codes}
	srv := httptest.NewServer(seq)
	t.Cleanup(srv.Close)
	c := New(srv.URL, WithPollInterval(4*time.Second))
	sleeps := new(int)
	c.sleep = func(ctx context.Context, d time.Duration) error {
		if d != 4*time.Second {
			t.Errorf("slept %s", d)
		}
		*sleeps++
		return nil
	}
	return c, seq, sleeps
}

// The wait tests mirror the runs of spec/capture_lifecycle.qnt (WAIT_TIMEOUT 12, POLL_INTERVAL 4).
const specTimeout = 12 * time.Second

func TestWait_ongoingThenDoneTest(t *testing.T) {
	c, seq, sleeps := waitClient(t, StatusOngoing, StatusDone)
	w, err := c.Wait(context.Background(), testCapture, specTimeout)
	if err != nil || w.Outcome != OutcomeDone || w.StatusCode != StatusDone || w.Polls != 2 || seq.count() != 2 || *sleeps != 1 {
		t.Errorf("wait = %+v, %v (polls %d, sleeps %d)", w, err, seq.count(), *sleeps)
	}
}

func TestWait_queuedOngoingDoneTest(t *testing.T) {
	c, _, _ := waitClient(t, StatusQueued, StatusOngoing, StatusDone)
	w, err := c.Wait(context.Background(), testCapture, specTimeout)
	if err != nil || w.Outcome != OutcomeDone || w.Polls != 3 {
		t.Errorf("wait = %+v, %v", w, err)
	}
}

func TestWait_persistentUnknownTest(t *testing.T) {
	c, seq, _ := waitClient(t, StatusUnknown)
	_, err := c.Wait(context.Background(), testCapture, specTimeout)
	if !errors.Is(err, ErrPersistentUnknown) || seq.count() != MaxUnknownPolls {
		t.Errorf("err = %v after %d polls", err, seq.count())
	}
}

func TestWait_unknownStreakResetsTest(t *testing.T) {
	c, seq, _ := waitClient(t, StatusUnknown, StatusUnknown, StatusQueued, StatusUnknown)
	w, err := c.Wait(context.Background(), testCapture, specTimeout)
	if err != nil || w.Outcome != OutcomeTimedOut || seq.count() != 4 || w.StatusCode != StatusUnknown {
		t.Errorf("wait = %+v, %v (polls %d)", w, err, seq.count())
	}
}

func TestWait_timeoutTest(t *testing.T) {
	c, seq, sleeps := waitClient(t, StatusOngoing)
	w, err := c.Wait(context.Background(), testCapture, specTimeout)
	if err != nil || w.Outcome != OutcomeTimedOut || w.StatusCode != StatusOngoing {
		t.Fatalf("wait = %+v, %v", w, err)
	}
	if bound := int(specTimeout/(4*time.Second)) + 1; seq.count() != bound || *sleeps != bound-1 {
		t.Errorf("%d polls and %d sleeps, want %d and %d", seq.count(), *sleeps, bound, bound-1)
	}
}

func TestWaitPollBoundForEveryTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{time.Second, 4 * time.Second, 5 * time.Second, 120 * time.Second} {
		c, seq, _ := waitClient(t, StatusQueued)
		if _, err := c.Wait(context.Background(), testCapture, timeout); err != nil {
			t.Fatal(err)
		}
		if bound := int(timeout/(4*time.Second)) + 1; seq.count() > bound {
			t.Errorf("timeout %s: %d polls, bound %d", timeout, seq.count(), bound)
		}
	}
}

func TestWaitStopsWhenTheContextEnds(t *testing.T) {
	c, seq, _ := waitClient(t, StatusOngoing)
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return sleepCtx(ctx, d)
	}
	if _, err := c.Wait(ctx, testCapture, specTimeout); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if seq.count() != 1 {
		t.Errorf("%d polls", seq.count())
	}
}

func TestWaitRejectsBadInputBeforeHTTP(t *testing.T) {
	c := New(noCallServer(t).URL)
	for _, timeout := range []time.Duration{0, -time.Second, MaxWaitTimeout + time.Second} {
		if _, err := c.Wait(context.Background(), testCapture, timeout); err == nil {
			t.Errorf("timeout %s was accepted", timeout)
		}
	}
	if _, err := c.Wait(context.Background(), "nope", time.Second); err == nil {
		t.Error("an invalid UUID was accepted")
	}
}

func TestParseSubmitResponse(t *testing.T) {
	for _, body := range []string{string(fixture(t, "submit_response.txt")), testCapture, " " + testCapture + "\n", `"` + strings.ToUpper(testCapture) + `"`} {
		id, err := ParseSubmitResponse([]byte(body))
		if err != nil || id != testCapture {
			t.Errorf("ParseSubmitResponse(%q) = %q, %v", body, id, err)
		}
	}
	for _, body := range []string{"", `""`, "<html>", `{"error": "No URL"}`, testCapture + "x"} {
		if _, err := ParseSubmitResponse([]byte(body)); err == nil {
			t.Errorf("ParseSubmitResponse(%q) was accepted", body)
		}
	}
}

func submitServer(t *testing.T, status int, response string) (*httptest.Server, *[]byte) {
	t.Helper()
	got := new([]byte)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/submit" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		*got, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestSubmitDefaultsToUnlisted(t *testing.T) {
	srv, got := submitServer(t, http.StatusOK, string(fixture(t, "submit_response.txt")))
	id, err := New(srv.URL).Submit(context.Background(), SubmitParams{URL: "https://example.com/"})
	if err != nil || id != testCapture {
		t.Fatalf("Submit = %q, %v", id, err)
	}
	var body map[string]any
	if err := json.Unmarshal(*got, &body); err != nil {
		t.Fatal(err)
	}
	if body["listing"] != float64(0) || body["url"] != "https://example.com/" || len(body) != 2 {
		t.Errorf("body = %s", *got)
	}
}

func TestSubmitSendsEveryField(t *testing.T) {
	srv, got := submitServer(t, http.StatusOK, testCapture)
	yes, no := true, false
	_, err := New(srv.URL).Submit(context.Background(), SubmitParams{
		Document: "PGh0bWw+PC9odG1sPg==", DocumentName: "page.html", Listing: true,
		AllowTracking: &no, JavaScriptEnabled: &yes, UserAgent: "UA", BrowserName: "Firefox",
		DeviceName: "Desktop Chrome HiDPI", Referer: "https://ref.example/", Headers: "Accept-Language: fr",
		Proxy: "socks5://u:p@127.0.0.1:1080", Cookies: `[{"name": "a", "value": "b"}]`,
		AutoReport: &AutoReport{Email: "a@example.org", Comment: "phish"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(*got, &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"document": "PGh0bWw+PC9odG1sPg==", "document_name": "page.html", "listing": float64(1),
		"allow_tracking": float64(0), "java_script_enabled": float64(1), "user_agent": "UA", "browser_name": "firefox",
		"device_name": "Desktop Chrome HiDPI", "referer": "https://ref.example/", "headers": "Accept-Language: fr",
		"proxy": "socks5://u:p@127.0.0.1:1080", "cookies": `[{"name": "a", "value": "b"}]`,
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v", k, body[k], v)
		}
	}
	if ar, _ := body["auto_report"].(map[string]any); ar["email"] != "a@example.org" || ar["comment"] != "phish" {
		t.Errorf("auto_report = %v", body["auto_report"])
	}
	if _, ok := body["url"]; ok {
		t.Errorf("url sent with a document")
	}
}

func TestSubmitValidatesBeforeHTTP(t *testing.T) {
	c := New(noCallServer(t).URL)
	cases := []SubmitParams{
		{},
		{URL: "https://example.com/", Document: "eA=="},
		{URL: "https://exa mple.com/"},
		{URL: "https://example.com/\r\nX: y"},
		{Document: "not base64!", DocumentName: "x.html"},
		{Document: "eA=="},
		{Document: "eA==", DocumentName: "../x.html"},
		{URL: "https://example.com/", BrowserName: "edge"},
		{URL: "https://example.com/", Proxy: "not a proxy"},
		{URL: "https://example.com/", Cookies: "{nope"},
	}
	for _, p := range cases {
		if _, err := c.Submit(context.Background(), p); err == nil {
			t.Errorf("%+v was accepted", p)
		}
	}
}

func TestSubmitNeverLeaksTheProxy(t *testing.T) {
	proxy := "http://analyst:Sup3rS3cret@proxy.internal:3128"
	echo := `{"message": "Unable to validate capture settings.", "details": [{"input": "` + proxy + `", "msg": "bad"}, {"input": "Sup3rS3cret"}]}`
	srv, _ := submitServer(t, http.StatusBadRequest, echo)
	_, err := New(srv.URL).Submit(context.Background(), SubmitParams{URL: "https://example.com/", Proxy: proxy})
	if err == nil {
		t.Fatal("a 400 was accepted")
	}
	for _, secret := range []string{proxy, "Sup3rS3cret", "analyst:Sup3rS3cret"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error leaks %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "[redacted]") || !strings.Contains(err.Error(), "HTTP 400") {
		t.Errorf("err = %v", err)
	}
}

func TestTriggerModules(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/json/"+testCapture+"/trigger_modules" || r.Method != http.MethodPost {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		body, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"vt": "Module not enabled."}`))
	}))
	defer srv.Close()
	raw, err := New(srv.URL).TriggerModules(context.Background(), testCapture, true)
	if err != nil || !strings.Contains(string(raw), "vt") || string(body) != `{"force":true}` {
		t.Errorf("TriggerModules = %s, %v, body %s", raw, err, body)
	}
	if _, err := New(noCallServer(t).URL).TriggerModules(context.Background(), "x", false); err == nil {
		t.Error("an invalid UUID was accepted")
	}
}
