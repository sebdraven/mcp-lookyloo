package mcptools

import (
	"context"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
)

var (
	readTools  = slices.Concat(captureTools, artefactTools, searchTools, []string{"lk_devices", "lk_instance_stats", "lk_user_config"})
	pushTools  = []string{"lk_capture_report", "lk_misp_push", "lk_upload_capture"}
	adminTools = []string{"lk_admin_hide", "lk_admin_rebuild", "lk_admin_remove", "lk_admin_rebuild_cache", "lk_admin_rebuild_all"}
)

func registered(opts Options) []string {
	s := mcp.NewServer(&mcp.Implementation{Name: "lookyloo", Version: "test"}, nil)
	return Register(s, lookyloo.New("http://127.0.0.1:1"), opts)
}

// expectedTools is written independently of Options.allows, from SPEC §2.
func expectedTools(o Options) []string {
	if o.ReadOnly {
		return readTools
	}
	want := slices.Concat(readTools, submitTools)
	if o.AllowPush {
		want = slices.Concat(want, pushTools)
	}
	if o.AllowAdmin {
		want = slices.Concat(want, adminTools)
	}
	return want
}

func allOptions() []Options {
	var all []Options
	for _, ro := range []bool{false, true} {
		for _, push := range []bool{false, true} {
			for _, admin := range []bool{false, true} {
				all = append(all, Options{ReadOnly: ro, AllowPush: push, AllowAdmin: admin})
			}
		}
	}
	return all
}

func TestGatingExactToolsForEveryFlagCombination(t *testing.T) {
	for _, o := range allOptions() {
		if got, want := registered(o), expectedTools(o); !slices.Equal(got, want) {
			t.Errorf("%+v: registered %v, want %v", o, got, want)
		}
	}
}

func TestGating_countsTest(t *testing.T) {
	if n := len(ToolLevels); n != 35 {
		t.Errorf("%d tools have a level, want 35", n)
	}
	counts := []struct {
		opts Options
		want int
	}{
		{Options{}, 27},
		{Options{AllowPush: true}, 30},
		{Options{AllowAdmin: true}, 32},
		{Options{AllowPush: true, AllowAdmin: true}, 35},
		{Options{ReadOnly: true, AllowPush: true, AllowAdmin: true}, 25},
	}
	for _, tc := range counts {
		if n := len(registered(tc.opts)); n != tc.want {
			t.Errorf("%+v: %d tools, want %d", tc.opts, n, tc.want)
		}
	}
}

func TestGating_defaultFlagsTest(t *testing.T) {
	got := registered(Options{})
	if !slices.Contains(got, "lk_submit") || slices.Contains(got, "lk_misp_push") || slices.Contains(got, "lk_admin_remove") {
		t.Errorf("default tools = %v", got)
	}
}

func TestGating_readOnlyBeatsEverythingTest(t *testing.T) {
	for _, tool := range registered(Options{ReadOnly: true, AllowPush: true, AllowAdmin: true}) {
		if ToolLevels[tool] != Read {
			t.Errorf("-read-only registered %s (level %s)", tool, ToolLevels[tool])
		}
	}
}

func TestGating_everythingTest(t *testing.T) {
	got := registered(Options{AllowPush: true, AllowAdmin: true})
	var all []string
	for name := range ToolLevels {
		all = append(all, name)
	}
	if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(all))) {
		t.Errorf("registered %v", got)
	}
	if slices.Contains(got, "lk_get_token") {
		t.Error("get_token must never be a tool")
	}
}

func TestGatingIsMonotone(t *testing.T) {
	leq := func(a, b Options) bool {
		return (a.ReadOnly || !b.ReadOnly) && (!a.AllowPush || b.AllowPush) && (!a.AllowAdmin || b.AllowAdmin)
	}
	for _, a := range allOptions() {
		for _, b := range allOptions() {
			if !leq(a, b) {
				continue
			}
			ra, rb := registered(a), registered(b)
			for _, tool := range ra {
				if !slices.Contains(rb, tool) {
					t.Errorf("%s is registered with %+v but not with %+v", tool, a, b)
				}
			}
		}
	}
}

func TestGatingAnnotations(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{AllowPush: true, AllowAdmin: true})
	res, err := e.session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 35 {
		t.Fatalf("%d tools listed", len(res.Tools))
	}
	for _, tool := range res.Tools {
		a := tool.Annotations
		if a == nil || a.OpenWorldHint == nil {
			t.Fatalf("%s has no annotations", tool.Name)
		}
		level := ToolLevels[tool.Name]
		if a.ReadOnlyHint != (level == Read) {
			t.Errorf("%s (%s): readOnlyHint = %v", tool.Name, level, a.ReadOnlyHint)
		}
		if *a.OpenWorldHint != (level == Submit || level == Push) {
			t.Errorf("%s (%s): openWorldHint = %v", tool.Name, level, *a.OpenWorldHint)
		}
		if level != Read {
			wantDestructive := tool.Name == "lk_admin_remove"
			if a.DestructiveHint == nil || *a.DestructiveHint != wantDestructive {
				t.Errorf("%s: destructiveHint = %v, want %v", tool.Name, a.DestructiveHint, wantDestructive)
			}
		}
	}
}

func TestGating_autoReportRefusedWithoutPushTest(t *testing.T) {
	args := map[string]any{"url": "https://example.com/", "auto_report": map[string]any{"email": "a@example.org"}}

	e := start(t, map[string]reply{}, "", Options{})
	if res := e.call(t, "lk_submit", args); !res.IsError {
		t.Errorf("auto_report was accepted without -allow-push")
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}

	e = start(t, submitRoutes(statusDone), "", Options{AllowPush: true})
	var out submitResult
	decode(t, e.call(t, "lk_submit", args), &out)
	if ar, _ := submitBody(t, e)["auto_report"].(map[string]any); ar["email"] != "a@example.org" {
		t.Errorf("auto_report not sent with -allow-push")
	}
}

func TestUnclassifiedToolPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a tool without a level was registered")
		}
	}()
	r := &registry{client: lookyloo.New("http://127.0.0.1:1")}
	s := mcp.NewServer(&mcp.Implementation{Name: "lookyloo", Version: "test"}, nil)
	addTool(r, s, &mcp.Tool{Name: "lk_unclassified"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return nil, nil, nil
	})
}
