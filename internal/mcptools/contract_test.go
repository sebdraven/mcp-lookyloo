package mcptools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
)

const swaggerPath = "../../api/lookyloo-swagger-1.27.0.json"

// excluded lists the only operations that are not tools (SPEC §2.8): credentials never go through the model.
var excluded = map[string]string{
	"POST /json/get_token": "post_auth_token",
	"GET /json/get_token":  "get_auth_token",
}

// An unused GET variant (viaPost) is covered by the POST variant of the same endpoint.
type mapping struct {
	key         string
	operationID string
	tool        string
	args        map[string]any
	viaPost     bool
}

func captureArgs() map[string]any { return map[string]any{"capture_uuid": captureUUID} }

var contractList = []mapping{
	{"GET /json/{capture_uuid}/info", "get_capture_info", "lk_capture_info", captureArgs(), false},
	{"GET /json/{capture_uuid}/status", "get_capture_status_query", "lk_capture_status", captureArgs(), false},
	{"GET /json/{capture_uuid}/stats", "get_capture_stats", "lk_capture_stats", captureArgs(), false},
	{"GET /json/{capture_uuid}/redirects", "get_capture_redirects", "lk_capture_redirects", captureArgs(), false},
	{"GET /json/{capture_uuid}/urls", "get_capture_ur_ls", "lk_capture_urls", captureArgs(), false},
	{"GET /json/{capture_uuid}/hostnames", "get_capture_hostnames", "lk_capture_hostnames", captureArgs(), false},
	{"GET /json/{capture_uuid}/hashes", "get_capture_hashes", "lk_capture_hashes", captureArgs(), false},
	{"GET /json/{capture_uuid}/cookies", "get_capture_cookies", "lk_capture_cookies", captureArgs(), false},
	{"GET /json/{capture_uuid}/comparables", "get_comparables", "lk_capture_comparables", captureArgs(), false},
	{"GET /json/{capture_uuid}/modules", "get_modules_response", "lk_capture_modules", captureArgs(), false},
	{"GET /json/{capture_uuid}/misp_export", "get_misp_export", "lk_capture_misp_export", captureArgs(), false},

	{"GET /bin/{capture_uuid}/screenshot", "get_capture_screenshot", "lk_capture_screenshot", captureArgs(), false},
	{"GET /bin/{capture_uuid}/data", "get_capture_data", "lk_capture_data", captureArgs(), false},
	{"GET /bin/{capture_uuid}/export", "get_capture_export", "lk_capture_export", captureArgs(), false},

	{"POST /json/url_info", "post_url_info", "lk_url_info", map[string]any{"url": "https://example.com/"}, false},
	{"POST /json/hostname_info", "post_hostname_info", "lk_hostname_info", map[string]any{"hostname": "example.com"}, false},
	{"GET /json/hash_info/{h}", "get_hash_info", "lk_hash_info", map[string]any{"h": strings.Repeat("ab", 64)}, false},
	{"GET /json/tlds", "get_tld_captures", "lk_tld_captures", map[string]any{"tld": "com"}, false},
	{"GET /json/categories", "get_categories_captures", "lk_categories", map[string]any{}, false},
	{"GET /json/categories/{category}", "get_categories_captures", "lk_categories", map[string]any{"category": "phishing"}, false},
	{"GET /json/recent_captures", "get_recent_captures", "lk_recent_captures", map[string]any{}, false},
	{"GET /json/recent_captures/{timestamp}", "get_recent_captures", "lk_recent_captures", map[string]any{"timestamp": "1795285600"}, false},
	{"POST /json/compare_captures", "post_compare_captures", "lk_compare_captures", map[string]any{"capture_left": captureUUID, "capture_right": unknownUUID}, false},
	{"POST /json/takedown", "post_takedown", "lk_takedown_info", captureArgs(), false},

	{"GET /json/devices", "get_devices", "lk_devices", map[string]any{}, false},
	{"GET /json/stats", "get_instance_stats", "lk_instance_stats", map[string]any{}, false},
	{"GET /json/get_user_config", "get_user_config", "lk_user_config", map[string]any{}, false},

	{"POST /submit", "post_submit_capture", "lk_submit", map[string]any{"url": "https://example.com/"}, false},
	{"GET /submit", "get_submit_capture", "lk_submit", nil, true},
	{"POST /json/{capture_uuid}/trigger_modules", "post_trigger_modules", "lk_trigger_modules", captureArgs(), false},

	{"POST /json/{capture_uuid}/report", "post_capture_report", "lk_capture_report", captureArgs(), false},
	{"POST /json/{capture_uuid}/misp_push", "post_misp_push", "lk_misp_push", captureArgs(), false},
	{"GET /json/{capture_uuid}/misp_push", "get_misp_push", "lk_misp_push", nil, true},
	{"POST /json/{capture_uuid}/misp_push/{instance_name}", "post_misp_push", "lk_misp_push", map[string]any{"capture_uuid": captureUUID, "instance_name": "misp"}, false},
	{"GET /json/{capture_uuid}/misp_push/{instance_name}", "get_misp_push", "lk_misp_push", nil, true},
	{"POST /json/upload", "post_upload_capture", "lk_upload_capture", map[string]any{"full_capture": "UEsDBA=="}, false},

	{"POST /admin/{capture_uuid}/hide", "post_capture_hide", "lk_admin_hide", captureArgs(), false},
	{"POST /admin/{capture_uuid}/rebuild", "post_capture_rebuild_tree", "lk_admin_rebuild", captureArgs(), false},
	{"POST /admin/{capture_uuid}/remove", "post_capture_remove", "lk_admin_remove", captureArgs(), false},
	{"POST /admin/rebuild_all_cache", "post_rebuild_all_cache", "lk_admin_rebuild_cache", map[string]any{}, false},
	{"POST /admin/rebuild_all", "post_rebuild_all", "lk_admin_rebuild_all", map[string]any{}, false},
}

func contractMap(t *testing.T) map[string]mapping {
	t.Helper()
	m := map[string]mapping{}
	for _, c := range contractList {
		if _, dup := m[c.key]; dup {
			t.Fatalf("%s is mapped twice", c.key)
		}
		m[c.key] = c
	}
	return m
}

type swaggerInfo struct {
	Version string `json:"version"`
}

type swaggerDoc struct {
	Info  swaggerInfo                           `json:"info"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

type swaggerOp struct {
	key         string
	operationID string
	security    bool
}

func swaggerOperations(t *testing.T) []swaggerOp {
	t.Helper()
	b, err := os.ReadFile(swaggerPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc swaggerDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Info.Version != "1.27.0" {
		t.Errorf("swagger version %q", doc.Info.Version)
	}
	var ops []swaggerOp
	for path, methods := range doc.Paths {
		for method, raw := range methods {
			if method == "parameters" {
				continue
			}
			var op struct {
				OperationID string           `json:"operationId"`
				Security    []map[string]any `json:"security"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			ops = append(ops, swaggerOp{key: strings.ToUpper(method) + " " + path, operationID: op.OperationID, security: len(op.Security) > 0})
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].key < ops[j].key })
	return ops
}

func TestContractEveryOperationIsMappedOrExcluded(t *testing.T) {
	ops := swaggerOperations(t)
	if len(ops) != 43 {
		t.Errorf("the swagger has %d operations, SPEC §2 counts 43", len(ops))
	}
	contract := contractMap(t)
	seen := map[string]bool{}
	for _, op := range ops {
		seen[op.key] = true
		if id, ok := excluded[op.key]; ok {
			if id != op.operationID {
				t.Errorf("%s: excluded as %s, swagger says %s", op.key, id, op.operationID)
			}
			continue
		}
		m, ok := contract[op.key]
		if !ok {
			t.Errorf("%s (%s) is neither mapped to a tool nor excluded", op.key, op.operationID)
			continue
		}
		if m.operationID != op.operationID {
			t.Errorf("%s: mapped as %s, swagger says %s", op.key, m.operationID, op.operationID)
		}
	}
	for key := range contract {
		if !seen[key] {
			t.Errorf("%s is mapped but not in the swagger", key)
		}
	}
	for key := range excluded {
		if !seen[key] {
			t.Errorf("%s is excluded but not in the swagger", key)
		}
	}
}

func TestContractOnlyGetTokenIsExcluded(t *testing.T) {
	want := []string{"GET /json/get_token", "POST /json/get_token"}
	var got []string
	for key := range excluded {
		got = append(got, key)
	}
	if !slices.Equal(slices.Sorted(slices.Values(got)), want) {
		t.Errorf("excluded = %v, want exactly %v (SPEC §2.8)", got, want)
	}
	for _, tool := range registered(Options{AllowPush: true, AllowAdmin: true}) {
		if strings.Contains(tool, "token") {
			t.Errorf("%s exposes get_token", tool)
		}
	}
}

func TestContractToolsMatchTheLevels(t *testing.T) {
	mapped := map[string]bool{}
	for key, m := range contractMap(t) {
		if _, ok := ToolLevels[m.tool]; !ok {
			t.Errorf("%s maps to %s, which has no level", key, m.tool)
		}
		mapped[m.tool] = true
	}
	for tool := range ToolLevels {
		if !mapped[tool] {
			t.Errorf("%s covers no operation of the swagger", tool)
		}
	}
	if len(mapped) != 35 {
		t.Errorf("%d tools cover the swagger, SPEC §2 counts 35", len(mapped))
	}
}

func TestContractAuthenticatedOperationsNeedAToken(t *testing.T) {
	contract := contractMap(t)
	for _, op := range swaggerOperations(t) {
		m, ok := contract[op.key]
		if !ok || !op.security || m.viaPost {
			continue
		}
		e := start(t, map[string]reply{}, "", Options{AllowPush: true, AllowAdmin: true, OutDir: t.TempDir()})
		res := e.call(t, m.tool, m.args)
		if !res.IsError || !strings.Contains(text(res), lookyloo.EnvAPIKey) {
			t.Errorf("%s (apikey) without a token: %s", op.key, text(res))
		}
		if n := len(e.fake.requests()); n != 0 {
			t.Errorf("%s reached HTTP without a token", op.key)
		}
	}
}

func templateRe(path string) *regexp.Regexp {
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			segs[i] = "[^/]+"
		} else {
			segs[i] = regexp.QuoteMeta(seg)
		}
	}
	return regexp.MustCompile("^" + strings.Join(segs, "/") + "$")
}

func TestTemplateRe(t *testing.T) {
	re := templateRe("/json/{capture_uuid}/misp_push/{instance_name}")
	push := "/json/" + captureUUID + "/misp_push"
	if !re.MatchString(push+"/misp") || re.MatchString(push) || re.MatchString("/json/a/b/misp_push/c") {
		t.Error("templateRe does not match path templates segment by segment")
	}
}

// anything answers every Lookyloo endpoint with a body the client accepts.
func anything(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/status"):
		fmt.Fprint(w, `{"status_code": 1}`)
	case strings.HasSuffix(p, "/screenshot"):
		w.Write([]byte("\x89PNG\r\n\x1a\n"))
	case strings.HasPrefix(p, "/bin/"):
		w.Write([]byte("PK\x03\x04"))
	case p == "/submit":
		fmt.Fprintf(w, "%q", captureUUID)
	case p == "/json/upload":
		fmt.Fprintf(w, `{"uuid": %q}`, captureUUID)
	case p == "/json/url_info", p == "/json/hostname_info", strings.HasPrefix(p, "/json/recent_captures"):
		fmt.Fprint(w, `[]`)
	case strings.HasSuffix(p, "/urls"):
		fmt.Fprint(w, `{"response": {"urls": []}}`)
	case strings.HasSuffix(p, "/hostnames"):
		fmt.Fprint(w, `{"response": {"hostnames": []}}`)
	case strings.HasSuffix(p, "/hashes"):
		fmt.Fprint(w, `{"response": {"hashes": []}}`)
	default:
		fmt.Fprint(w, `{}`)
	}
}

func TestContractEveryMappedOperationIsReallyCalled(t *testing.T) {
	for _, m := range contractList {
		if m.viaPost {
			continue
		}
		t.Run(m.key, func(t *testing.T) {
			var mu sync.Mutex
			var calls []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls = append(calls, r.Method+" "+r.URL.Path)
				mu.Unlock()
				anything(w, r)
			}))
			defer srv.Close()

			c := lookyloo.New(srv.URL, lookyloo.WithTokenSource(lookyloo.StaticToken("TOKEN")))
			s := mcp.NewServer(&mcp.Implementation{Name: "lookyloo", Version: "test"}, nil)
			Register(s, c, Options{AllowPush: true, AllowAdmin: true, OutDir: t.TempDir()})
			res, err := connect(t, s).CallTool(t.Context(), &mcp.CallToolParams{Name: m.tool, Arguments: m.args})
			if err != nil {
				t.Fatalf("%s: %v", m.tool, err)
			}
			if res.IsError {
				t.Fatalf("%s: %s", m.tool, text(res))
			}
			method, path, _ := strings.Cut(m.key, " ")
			re := templateRe(path)
			mu.Lock()
			defer mu.Unlock()
			for _, call := range calls {
				cm, cp, _ := strings.Cut(call, " ")
				if cm == method && re.MatchString(cp) {
					return
				}
			}
			t.Errorf("%s never sent %s; it sent %v", m.tool, m.key, calls)
		})
	}
}
