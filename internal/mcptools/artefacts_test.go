package mcptools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var artefactTools = []string{"lk_capture_screenshot", "lk_capture_data", "lk_capture_export"}

func statusRoute(id, fixture string) map[string]reply {
	return map[string]reply{"GET /json/" + id + "/status": {fixture: fixture}}
}

func with(routes map[string]reply, key string, rep reply) map[string]reply {
	routes[key] = rep
	return routes
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type artefactResult struct {
	CaptureUUID      string `json:"capture_uuid"`
	Path             string `json:"path"`
	Size             int64  `json:"size"`
	SHA256           string `json:"sha256"`
	EntriesTruncated bool   `json:"entries_truncated"`
	Entries          []struct {
		Name string `json:"name"`
		Size uint64 `json:"size"`
	} `json:"entries"`
}

func TestScreenshotInlineAndSaved(t *testing.T) {
	png := readFixture(t, "capture_screenshot.png")
	dir := t.TempDir()
	routes := with(statusRoute(captureUUID, "capture_status.json"), "GET /bin/"+captureUUID+"/screenshot",
		reply{fixture: "capture_screenshot.png", ctype: "image/png"})
	e := start(t, routes, "", Options{})

	res := e.call(t, "lk_capture_screenshot", map[string]any{"capture_uuid": captureUUID, "out_dir": dir})
	if res.IsError {
		t.Fatal(text(res))
	}
	img, ok := res.Content[0].(*mcp.ImageContent)
	if !ok || img.MIMEType != "image/png" || !bytes.Equal(img.Data, png) {
		t.Fatalf("content = %#v", res.Content)
	}
	var out artefactResult
	decode(t, res, &out)
	want := filepath.Join(dir, captureUUID+".png")
	if out.Path != want || out.Size != int64(len(png)) || out.SHA256 != sha256Hex(png) || len(out.SHA256) != 64 {
		t.Errorf("output = %+v", out)
	}
	saved, err := os.ReadFile(want)
	if err != nil || !bytes.Equal(saved, png) {
		t.Errorf("saved file: %v", err)
	}
	fi, err := os.Stat(want)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestScreenshotFallsBackToFlagOrNoFile(t *testing.T) {
	routes := func() map[string]reply {
		return with(statusRoute(captureUUID, "capture_status.json"), "GET /bin/"+captureUUID+"/screenshot",
			reply{fixture: "capture_screenshot.png", ctype: "image/png"})
	}
	dir := t.TempDir()
	e := start(t, routes(), "", Options{OutDir: dir})
	var out artefactResult
	decode(t, e.call(t, "lk_capture_screenshot", map[string]any{"capture_uuid": captureUUID}), &out)
	if out.Path != filepath.Join(dir, captureUUID+".png") {
		t.Errorf("path = %q, want the -out directory", out.Path)
	}

	e = start(t, routes(), "", Options{})
	res := e.call(t, "lk_capture_screenshot", map[string]any{"capture_uuid": captureUUID})
	var bare artefactResult
	decode(t, res, &bare)
	if bare.Path != "" {
		t.Errorf("a file was written without out_dir: %q", bare.Path)
	}
	if _, ok := res.Content[0].(*mcp.ImageContent); !ok {
		t.Errorf("no inline image without out_dir")
	}
}

func TestArchivesAreWrittenNeverInline(t *testing.T) {
	cases := []struct {
		tool    string
		kind    string
		fixture string
		entries []string
	}{
		{"lk_capture_data", "data", "capture_data.zip", []string{"no_download"}},
		{"lk_capture_export", "export", "capture_export.zip", []string{
			"2026-11-21T18:27:35.313206/0.last_redirect.txt", "2026-11-21T18:27:35.313206/uuid",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			zipBytes := readFixture(t, tc.fixture)
			dir := filepath.Join(t.TempDir(), "nested", "out")
			routes := with(statusRoute(captureUUID, "capture_status.json"), "GET /bin/"+captureUUID+"/"+tc.kind,
				reply{fixture: tc.fixture, ctype: "application/zip"})
			e := start(t, routes, "", Options{})

			res := e.call(t, tc.tool, map[string]any{"capture_uuid": captureUUID, "out_dir": dir})
			if res.IsError {
				t.Fatal(text(res))
			}
			for _, c := range res.Content {
				if _, ok := c.(*mcp.TextContent); !ok {
					t.Errorf("non-text content %T in the response", c)
				}
			}
			if strings.Contains(text(res), "PK\x03\x04") {
				t.Errorf("the ZIP leaked into the response")
			}
			var out artefactResult
			decode(t, res, &out)
			want := filepath.Join(dir, captureUUID+"-"+tc.kind+".zip")
			if out.Path != want || out.Size != int64(len(zipBytes)) || out.SHA256 != sha256Hex(zipBytes) {
				t.Errorf("output = %+v", out)
			}
			saved, err := os.ReadFile(want)
			if err != nil || !bytes.Equal(saved, zipBytes) {
				t.Errorf("saved file differs: %v", err)
			}
			var names []string
			for _, en := range out.Entries {
				names = append(names, en.Name)
			}
			if strings.Join(names, ",") != strings.Join(tc.entries, ",") {
				t.Errorf("entries = %v", names)
			}
			files, _ := os.ReadDir(dir)
			if len(files) != 1 {
				t.Errorf("%d files in out_dir, want only the archive", len(files))
			}
		})
	}
}

func TestArchivesNeedAnOutDirBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{})
	for _, tool := range []string{"lk_capture_data", "lk_capture_export"} {
		res := e.call(t, tool, map[string]any{"capture_uuid": captureUUID})
		if !res.IsError || !strings.Contains(text(res), "-out") || !strings.Contains(text(res), "out_dir") {
			t.Errorf("%s: %s", tool, text(res))
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestArtefactsOfAnUnknownCapture(t *testing.T) {
	dir := t.TempDir()
	e := start(t, statusRoute(unknownUUID, "status_unknown.json"), "", Options{})
	for _, tool := range artefactTools {
		res := e.call(t, tool, map[string]any{"capture_uuid": unknownUUID, "out_dir": dir})
		if !res.IsError || !strings.Contains(text(res), "unknown") {
			t.Errorf("%s: %s", tool, text(res))
		}
	}
	for _, r := range e.fake.requests() {
		if !strings.HasSuffix(r.path, "/status") {
			t.Errorf("an artefact was requested for an unknown capture: %s", r.path)
		}
	}
	if files, _ := os.ReadDir(dir); len(files) != 0 {
		t.Errorf("%d files written", len(files))
	}
}

func TestArtefactsOfAnOngoingCapture(t *testing.T) {
	e := start(t, map[string]reply{"GET /json/" + captureUUID + "/status": {body: `{"status_code": 2}`}}, "", Options{})
	for _, tool := range artefactTools {
		res := e.call(t, tool, map[string]any{"capture_uuid": captureUUID, "out_dir": t.TempDir()})
		if !res.IsError || !strings.Contains(text(res), "not done yet (status 2)") {
			t.Errorf("%s: %s", tool, text(res))
		}
	}
}

func TestArtefactsRejectBodiesThatAreNotPNGOrZIP(t *testing.T) {
	dir := t.TempDir()
	routes := statusRoute(captureUUID, "capture_status.json")
	routes["GET /bin/"+captureUUID+"/screenshot"] = reply{fixture: "unknown_screenshot.bin", ctype: "image/png"}
	routes["GET /bin/"+captureUUID+"/export"] = reply{fixture: "unknown_export.bin", ctype: "application/zip"}
	routes["GET /bin/"+captureUUID+"/data"] = reply{body: "<html>proxy error</html>", ctype: "application/zip"}
	e := start(t, routes, "", Options{})

	if res := e.call(t, "lk_capture_screenshot", map[string]any{"capture_uuid": captureUUID, "out_dir": dir}); !res.IsError || !strings.Contains(text(res), "not a PNG") {
		t.Errorf("screenshot: %s", text(res))
	}
	for _, tool := range []string{"lk_capture_export", "lk_capture_data"} {
		if res := e.call(t, tool, map[string]any{"capture_uuid": captureUUID, "out_dir": dir}); !res.IsError || !strings.Contains(text(res), "not a ZIP") {
			t.Errorf("%s: %s", tool, text(res))
		}
	}
	if files, _ := os.ReadDir(dir); len(files) != 0 {
		t.Errorf("files left behind: %v", files)
	}
}

func TestArtefactsRejectInvalidUUIDBeforeHTTP(t *testing.T) {
	e := start(t, map[string]reply{}, "", Options{OutDir: t.TempDir()})
	for _, tool := range artefactTools {
		for _, bad := range []string{"", "x", "../../etc/passwd", captureUUID + "/../x"} {
			if res := e.call(t, tool, map[string]any{"capture_uuid": bad}); !res.IsError {
				t.Errorf("%s(%q) was accepted", tool, bad)
			}
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}
