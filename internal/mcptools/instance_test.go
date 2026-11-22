package mcptools

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestInstanceToolsNominal(t *testing.T) {
	cases := []struct {
		tool    string
		path    string
		fixture string
		want    string
	}{
		{"lk_devices", "/json/devices", "devices.json", `"Desktop Chrome HiDPI"`},
		{"lk_instance_stats", "/json/stats", "instance_stats.json", `"week_number"`},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			e := start(t, map[string]reply{"GET " + tc.path: {fixture: tc.fixture}}, "", Options{})
			res := e.call(t, tc.tool, map[string]any{})
			if res.IsError || !strings.Contains(text(res), tc.want) {
				t.Errorf("result = %.300s", text(res))
			}
		})
	}
}

func TestInstanceToolsHTTPError(t *testing.T) {
	for _, tc := range [][2]string{{"lk_devices", "/json/devices"}, {"lk_instance_stats", "/json/stats"}} {
		e := start(t, map[string]reply{"GET " + tc[1]: {status: http.StatusNotFound, body: `{"message": "not found"}`}}, "", Options{})
		res := e.call(t, tc[0], map[string]any{})
		if !res.IsError || !strings.Contains(text(res), "HTTP 404") {
			t.Errorf("%s: %s", tc[0], text(res))
		}
	}
}

func TestInstanceToolsRejectUnknownArguments(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	for _, tool := range []string{"lk_devices", "lk_instance_stats", "lk_user_config"} {
		if res := e.call(t, tool, map[string]any{"capture_uuid": captureUUID}); !res.IsError {
			t.Errorf("%s accepted an unknown argument", tool)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestUserConfigSendsToken(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/get_user_config": {fixture: "user_config_synthetic.json"}}, "TOKEN", Options{})
	res := e.call(t, "lk_user_config", map[string]any{})
	if res.IsError || !strings.Contains(text(res), `"listing": false`) {
		t.Fatalf("result = %s", text(res))
	}
	if h := e.fake.requests()[0].header.Get("Authorization"); h != "TOKEN" {
		t.Errorf("Authorization = %q", h)
	}
}

func TestUserConfigWithoutTokenFailsBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	res := e.call(t, "lk_user_config", map[string]any{})
	if !res.IsError || !strings.Contains(text(res), "LOOKYLOO_API_KEY") {
		t.Errorf("result = %s", text(res))
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests without a token", n)
	}
}

func TestUserConfigRejectedToken(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/get_user_config": {status: http.StatusForbidden, fixture: "error_user_config_noauth.json"}}, "BAD", Options{})
	res := e.call(t, "lk_user_config", map[string]any{})
	if !res.IsError || !strings.Contains(text(res), "Authentication required") {
		t.Errorf("result = %s", text(res))
	}
}

func TestRegisteredTools(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	read := slices.Concat(captureTools, artefactTools, searchTools, []string{"lk_devices", "lk_instance_stats", "lk_user_config"})
	want := slices.Concat(read, submitTools)
	if !slices.Equal(e.names, want) {
		t.Errorf("Register returned %v, want %v", e.names, want)
	}
	res, err := e.session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, tool := range res.Tools {
		listed = append(listed, tool.Name)
		a := tool.Annotations
		if a == nil || a.OpenWorldHint == nil {
			t.Errorf("%s has no openWorldHint", tool.Name)
			continue
		}
		if slices.Contains(read, tool.Name) && (!a.ReadOnlyHint || *a.OpenWorldHint) {
			t.Errorf("%s: a read tool must be readOnlyHint=true, openWorldHint=false", tool.Name)
		}
		if slices.Contains(submitTools, tool.Name) && (a.ReadOnlyHint || !*a.OpenWorldHint || a.DestructiveHint == nil || *a.DestructiveHint) {
			t.Errorf("%s: a submit tool must be openWorldHint=true, not read-only, not destructive", tool.Name)
		}
	}
	slices.Sort(listed)
	if !slices.Equal(listed, slices.Sorted(slices.Values(want))) {
		t.Errorf("listed %v", listed)
	}
}
