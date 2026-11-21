package lookyloo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// authWorld mirrors the state of spec/auth.qnt.
type authWorld struct {
	env           map[string]string
	keychain      string
	getTokenOK    bool
	keychainCalls int
	getTokenCalls int
}

func (w *authWorld) resolver() *Resolver {
	return &Resolver{
		getenv: func(k string) string { return w.env[k] },
		keychain: func() string {
			w.keychainCalls++
			return w.keychain
		},
		getToken: func(_ context.Context, user, pass string) (string, error) {
			w.getTokenCalls++
			if !w.getTokenOK {
				return "", errors.New("user/password invalid")
			}
			return "FETCHED", nil
		},
	}
}

type recorder struct {
	mu      sync.Mutex
	headers []string
}

func (rec *recorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.headers = append(rec.headers, r.Header.Get("Authorization"))
		rec.mu.Unlock()
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (rec *recorder) got() []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]string(nil), rec.headers...)
}

func call(c *Client, mode authMode) error {
	_, err := c.doJSON(context.Background(), request{method: http.MethodGet, path: "/json/x", auth: mode})
	return err
}

func creds() map[string]string {
	return map[string]string{EnvUsername: "analyst", EnvPassword: "s3cret"}
}

func TestAuth_envWinsTest(t *testing.T) {
	env := creds()
	env[EnvAPIKey] = "ENV"
	w := &authWorld{env: env, keychain: "KEYCHAIN", getTokenOK: true}
	rec := &recorder{}
	c := New(rec.server(t).URL, WithTokenSource(w.resolver()))

	for range 3 {
		if err := call(c, authRequired); err != nil {
			t.Fatal(err)
		}
	}
	if w.keychainCalls != 0 || w.getTokenCalls != 0 {
		t.Errorf("keychain %d, get_token %d calls; env must win alone", w.keychainCalls, w.getTokenCalls)
	}
	for _, h := range rec.got() {
		if h != "ENV" {
			t.Errorf("Authorization = %q", h)
		}
	}
}

func TestAuth_keychainFallbackTest(t *testing.T) {
	w := &authWorld{env: creds(), keychain: "KEYCHAIN", getTokenOK: true}
	rec := &recorder{}
	c := New(rec.server(t).URL, WithTokenSource(w.resolver()))

	for range 2 {
		if err := call(c, authRequired); err != nil {
			t.Fatal(err)
		}
	}
	if w.keychainCalls != 1 || w.getTokenCalls != 0 {
		t.Errorf("keychain %d, get_token %d calls", w.keychainCalls, w.getTokenCalls)
	}
	if rec.got()[0] != "KEYCHAIN" || rec.got()[1] != "KEYCHAIN" {
		t.Errorf("headers = %q", rec.got())
	}
}

func TestAuth_getTokenOnceTest(t *testing.T) {
	w := &authWorld{env: creds(), getTokenOK: true}
	rec := &recorder{}
	c := New(rec.server(t).URL, WithTokenSource(w.resolver()))

	if err := call(c, authOptional); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := call(c, authRequired); err != nil {
			t.Fatal(err)
		}
	}
	if w.getTokenCalls != 1 {
		t.Errorf("get_token called %d times", w.getTokenCalls)
	}
	if len(rec.got()) != 3 {
		t.Fatalf("%d HTTP calls", len(rec.got()))
	}
	for _, h := range rec.got() {
		if h != "FETCHED" {
			t.Errorf("Authorization = %q", h)
		}
	}
}

func TestAuth_getTokenFailureNotRetriedTest(t *testing.T) {
	w := &authWorld{env: creds(), getTokenOK: false}
	c := New(noCallServer(t).URL, WithTokenSource(w.resolver()))

	for range 2 {
		err := call(c, authRequired)
		if !errors.Is(err, ErrNoToken) {
			t.Fatalf("err = %v, want ErrNoToken", err)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("the password leaked into the error: %v", err)
		}
	}
	if w.getTokenCalls != 1 {
		t.Errorf("get_token called %d times", w.getTokenCalls)
	}
}

func TestAuth_requiredWithoutTokenErrorsTest(t *testing.T) {
	w := &authWorld{env: map[string]string{}}
	rec := &recorder{}
	srv := rec.server(t)
	c := New(srv.URL, WithTokenSource(w.resolver()))

	err := call(c, authRequired)
	if !errors.Is(err, ErrNoToken) {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
	for _, src := range []string{EnvAPIKey, KeychainService, EnvUsername, EnvPassword, "/json/get_token"} {
		if !strings.Contains(err.Error(), src) {
			t.Errorf("the error does not name %s: %v", src, err)
		}
	}
	if len(rec.got()) != 0 {
		t.Fatalf("an authenticated call reached HTTP without a token")
	}
	if w.getTokenCalls != 0 {
		t.Errorf("get_token called %d times without credentials", w.getTokenCalls)
	}

	if err := call(c, authOptional); err != nil {
		t.Fatal(err)
	}
	if len(rec.got()) != 1 || rec.got()[0] != "" {
		t.Errorf("headers = %q", rec.got())
	}
}

func TestResolverIsSafeAndOnceUnderConcurrency(t *testing.T) {
	var calls atomic.Int32
	env := creds()
	r := &Resolver{
		getenv:   func(k string) string { return env[k] },
		keychain: func() string { return "" },
		getToken: func(context.Context, string, string) (string, error) {
			calls.Add(1)
			return "FETCHED", nil
		},
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, err := r.Token(context.Background()); err != nil || tok != "FETCHED" {
				t.Errorf("Token = %q, %v", tok, err)
			}
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("get_token called %d times", n)
	}
}

func TestAnonymousCallsNeverResolve(t *testing.T) {
	w := &authWorld{env: creds(), keychain: "KEYCHAIN", getTokenOK: true}
	rec := &recorder{}
	c := New(rec.server(t).URL, WithTokenSource(w.resolver()))
	if err := call(c, authNone); err != nil {
		t.Fatal(err)
	}
	if w.keychainCalls != 0 || w.getTokenCalls != 0 || rec.got()[0] != "" {
		t.Errorf("an anonymous call resolved a token: keychain %d, get_token %d, header %q",
			w.keychainCalls, w.getTokenCalls, rec.got()[0])
	}
}

func TestGetTokenPostsCredentialsWithoutAuthorization(t *testing.T) {
	var got authTokenFields
	var method, path, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, auth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"authkey": "AUTHKEY"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, WithTokenSource(StaticToken("SHOULD-NOT-BE-SENT")))
	tok, err := c.GetToken(context.Background(), "analyst", "s3cret")
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if tok != "AUTHKEY" {
		t.Errorf("token = %q", tok)
	}
	if method != http.MethodPost || path != "/json/get_token" {
		t.Errorf("request = %s %s", method, path)
	}
	if auth != "" {
		t.Errorf("get_token sent Authorization %q", auth)
	}
	if got.Username != "analyst" || got.Password != "s3cret" {
		t.Errorf("body = %+v", got)
	}
}

func TestGetTokenRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "User/Password invalid."}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL).GetToken(context.Background(), "analyst", "s3cret")
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusUnauthorized {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("the password leaked into the error: %v", err)
	}
}

func TestGetTokenValidatesBeforeCalling(t *testing.T) {
	c := New(noCallServer(t).URL)
	for _, tc := range [][2]string{{"", "p"}, {"u", ""}} {
		if _, err := c.GetToken(context.Background(), tc[0], tc[1]); err == nil {
			t.Errorf("GetToken(%q, %q) was accepted", tc[0], tc[1])
		}
	}
}

func TestStaticTokenEmptyIsNoToken(t *testing.T) {
	if _, err := StaticToken("").Token(context.Background()); !errors.Is(err, ErrNoToken) {
		t.Errorf("err = %v", err)
	}
}
