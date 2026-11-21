package lookyloo

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const KeychainService = "lookyloo"

const (
	EnvURL      = "LOOKYLOO_URL"
	EnvAPIKey   = "LOOKYLOO_API_KEY"
	EnvUsername = "LOOKYLOO_USERNAME"
	EnvPassword = "LOOKYLOO_PASSWORD"
)

var ErrNoToken = errors.New("no Lookyloo API token: set " + EnvAPIKey +
	", or store it in the macOS keychain under the service name " + KeychainService +
	" (security add-generic-password -s " + KeychainService + " -a \"$USER\" -w)" +
	", or set " + EnvUsername + " and " + EnvPassword + " so the token is fetched from /json/get_token")

func keyFrom(getenv func(string) string, keychain func() string) (string, error) {
	if k := strings.TrimSpace(getenv(EnvAPIKey)); k != "" {
		return k, nil
	}
	if k := strings.TrimSpace(keychain()); k != "" {
		return k, nil
	}
	return "", ErrNoToken
}

func keychainKey() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "security", "find-generic-password",
		"-s", KeychainService, "-w").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
