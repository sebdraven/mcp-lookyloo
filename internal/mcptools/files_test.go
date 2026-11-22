package mcptools

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "-----BEGIN OPENSSH PRIVATE KEY----- not for Lookyloo"

func mustRoot(t *testing.T, dir string) *FilesRoot {
	t.Helper()
	fr, err := NewFilesRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fr
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// sandbox is a files root with docs/lure.html inside, and a secret beside it, outside the root.
type sandbox struct {
	root    string
	outside string
}

func newSandbox(t *testing.T) sandbox {
	t.Helper()
	base := t.TempDir()
	sb := sandbox{root: filepath.Join(base, "root"), outside: filepath.Join(base, "id_ed25519")}
	write(t, filepath.Join(sb.root, "docs", "lure.html"), "<html>lure</html>")
	write(t, sb.outside, secret)
	return sb
}

var pathParams = []struct {
	tool string
	args map[string]any
}{
	{"lk_submit", map[string]any{"document_path": "PATH"}},
	{"lk_upload_capture", map[string]any{"full_capture_path": "PATH"}},
	{"lk_upload_capture", map[string]any{"har_file_path": "PATH"}},
	{"lk_upload_capture", map[string]any{"har_file": "e30=", "screenshot_path": "PATH"}},
	{"lk_upload_capture", map[string]any{"har_file": "e30=", "html_path": "PATH"}},
}

func withPath(args map[string]any, path string) map[string]any {
	out := map[string]any{}
	for k, v := range args {
		if v == "PATH" {
			v = path
		}
		out[k] = v
	}
	return out
}

func TestPathsAreRefusedWithoutFilesRoot(t *testing.T) {
	sb := newSandbox(t)
	e := start(t, map[string]reply{}, "", Options{AllowPush: true})
	for _, p := range pathParams {
		res := e.call(t, p.tool, withPath(p.args, sb.outside))
		if !res.IsError || !strings.Contains(text(res), "-files-root") {
			t.Errorf("%s %v: %s", p.tool, p.args, text(res))
		}
		if strings.Contains(text(res), secret) {
			t.Errorf("%s leaked the file", p.tool)
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests", n)
	}
}

func TestBase64VariantsWorkWithoutFilesRoot(t *testing.T) {
	e := start(t, with(submitRoutes(statusDone), "POST /json/upload", reply{body: `{"uuid": "` + captureUUID + `"}`}), "", Options{AllowPush: true})
	doc := base64.StdEncoding.EncodeToString([]byte("<html>lure</html>"))
	if res := e.call(t, "lk_submit", map[string]any{"document": doc, "document_name": "lure.html"}); res.IsError {
		t.Errorf("document: %s", text(res))
	}
	if res := e.call(t, "lk_upload_capture", map[string]any{"har_file": "e30="}); res.IsError {
		t.Errorf("har_file: %s", text(res))
	}
	if res := e.call(t, "lk_upload_capture", map[string]any{"full_capture": "UEsDBA=="}); res.IsError {
		t.Errorf("full_capture: %s", text(res))
	}
}

func TestPathsOutsideFilesRootAreRefused(t *testing.T) {
	sb := newSandbox(t)
	if err := os.Symlink(sb.outside, filepath.Join(sb.root, "docs", "key.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(sb.outside), filepath.Join(sb.root, "up")); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"absolute path outside":             sb.outside,
		"../ out of the root":               "../id_ed25519",
		"../ hidden in the middle":          "docs/../../id_ed25519",
		"absolute path with ../":            filepath.Join(sb.root, "..", "id_ed25519"),
		"symlink to a file outside":         "docs/key.html",
		"symlinked directory outside":       "up/id_ed25519",
		"directory inside the root":         "docs",
		"the root itself":                   ".",
		"missing file":                      "docs/missing.html",
		"system file":                       "/etc/passwd",
		"home directory":                    "~/.ssh/id_ed25519",
		"directory outside the root, as ..": "..",
	}
	e := start(t, map[string]reply{}, "", Options{AllowPush: true, FilesRoot: mustRoot(t, sb.root)})
	for name, path := range cases {
		for _, p := range pathParams {
			res := e.call(t, p.tool, withPath(p.args, path))
			if !res.IsError {
				t.Errorf("%s (%q) accepted by %s %v", name, path, p.tool, p.args)
				continue
			}
			if strings.Contains(text(res), secret) || strings.Contains(text(res), "not for Lookyloo") {
				t.Errorf("%s: the error discloses the file: %s", name, text(res))
			}
		}
	}
	if n := len(e.fake.requests()); n != 0 {
		t.Errorf("%d HTTP requests after refusals", n)
	}
}

func TestPathsInsideFilesRootAreRead(t *testing.T) {
	sb := newSandbox(t)
	if err := os.Symlink(filepath.Join(sb.root, "docs", "lure.html"), filepath.Join(sb.root, "alias.html")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(sb.root, "..notes.html"), "<html>dots</html>")
	fr := mustRoot(t, sb.root)
	want := base64.StdEncoding.EncodeToString([]byte("<html>lure</html>"))
	for _, path := range []string{"docs/lure.html", filepath.Join(sb.root, "docs", "lure.html"), "docs/./lure.html", "alias.html"} {
		e := start(t, submitRoutes(statusDone), "", Options{FilesRoot: fr})
		res := e.call(t, "lk_submit", map[string]any{"document_path": path})
		if res.IsError {
			t.Errorf("%q: %s", path, text(res))
			continue
		}
		body := submitBody(t, e)
		if body["document"] != want || body["document_name"] != filepath.Base(path) {
			t.Errorf("%q: document_name %v", path, body["document_name"])
		}
	}
	if _, _, err := fr.ReadFile("document_path", "..notes.html", 1<<10); err != nil {
		t.Errorf("a file whose name starts with .. was refused: %v", err)
	}
}

func TestReadFileRefusesABlankPath(t *testing.T) {
	fr := mustRoot(t, newSandbox(t).root)
	for _, path := range []string{"", "   "} {
		if _, _, err := fr.ReadFile("document_path", path, 1<<10); err == nil {
			t.Errorf("ReadFile(%q) was accepted", path)
		}
	}
}

func TestReadFileEnforcesTheSizeLimit(t *testing.T) {
	sb := newSandbox(t)
	fr := mustRoot(t, sb.root)
	if _, _, err := fr.ReadFile("document_path", "docs/lure.html", 4); err == nil || strings.Contains(err.Error(), "lure</html>") {
		t.Errorf("err = %v", err)
	}
}

func TestNewFilesRootNeedsAnExistingDirectory(t *testing.T) {
	sb := newSandbox(t)
	for _, dir := range []string{filepath.Join(sb.root, "missing"), sb.outside} {
		if _, err := NewFilesRoot(dir); err == nil {
			t.Errorf("NewFilesRoot(%q) was accepted", dir)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(sb.root, link); err != nil {
		t.Fatal(err)
	}
	fr := mustRoot(t, link)
	resolved, _ := filepath.EvalSymlinks(sb.root)
	if fr.Dir() != resolved {
		t.Errorf("Dir() = %q, want the resolved %q", fr.Dir(), resolved)
	}
	if _, _, err := fr.ReadFile("document_path", "docs/lure.html", 1<<10); err != nil {
		t.Errorf("a root given through a symlink: %v", err)
	}
}
