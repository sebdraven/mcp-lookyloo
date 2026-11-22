package lookyloo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

type StaticToken string

func (t StaticToken) Token(context.Context) (string, error) {
	if t == "" {
		return "", ErrNoToken
	}
	return string(t), nil
}

type GetTokenFunc func(ctx context.Context, username, password string) (string, error)

// Resolver walks env, keychain, then get_token (spec/auth.qnt). Only a token is cached: a failure is retried on the next call.
type Resolver struct {
	getenv   func(string) string
	keychain func() string
	getToken GetTokenFunc

	mu    sync.Mutex
	token string
}

func NewResolver(getToken GetTokenFunc) *Resolver {
	return &Resolver{getenv: os.Getenv, keychain: keychainKey, getToken: getToken}
}

func (r *Resolver) Token(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token != "" {
		return r.token, nil
	}
	t, err := r.resolve(ctx)
	if err != nil {
		return "", err
	}
	r.token = t
	return t, nil
}

func (r *Resolver) resolve(ctx context.Context) (string, error) {
	if k, err := keyFrom(r.getenv, r.keychain); err == nil {
		return k, nil
	}
	user := strings.TrimSpace(r.getenv(EnvUsername))
	pass := r.getenv(EnvPassword)
	if user == "" || pass == "" || r.getToken == nil {
		return "", ErrNoToken
	}
	t, err := r.getToken(ctx, user, pass)
	if err != nil {
		return "", fmt.Errorf("%w (get_token for %s failed: %v)", ErrNoToken, EnvUsername, err)
	}
	return t, nil
}

type authTokenFields struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *Client) GetToken(ctx context.Context, username, password string) (string, error) {
	if username == "" || password == "" {
		return "", errors.New("lookyloo get_token: username and password are required")
	}
	raw, err := c.doJSON(ctx, request{
		method: http.MethodPost,
		path:   "/json/get_token",
		body:   authTokenFields{Username: username, Password: password},
		auth:   authNone,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		AuthKey string `json:"authkey"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || strings.TrimSpace(out.AuthKey) == "" {
		return "", errors.New("lookyloo get_token: no authkey in the response")
	}
	return strings.TrimSpace(out.AuthKey), nil
}
