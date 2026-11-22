package mcptools

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FilesRoot is the only directory the *_path parameters may read from.
type FilesRoot struct {
	dir  string
	root *os.Root
}

// NewFilesRoot resolves dir once, at startup; a missing directory is an error.
func NewFilesRoot(dir string) (*FilesRoot, error) {
	abs, err := filepath.Abs(strings.TrimSpace(dir))
	if err != nil {
		return nil, fmt.Errorf("-files-root %q: %w", dir, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("-files-root %q: %w", dir, err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("-files-root %q: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("-files-root %q is not a directory", dir)
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, fmt.Errorf("-files-root %q: %w", dir, err)
	}
	return &FilesRoot{dir: resolved, root: root}, nil
}

func (fr *FilesRoot) Dir() string { return fr.dir }

func errNoFilesRoot(field string) error {
	return fmt.Errorf("%s: reading local files is disabled; start the server with -files-root <dir> to allow paths inside that directory, or pass the content as base64", field)
}

// ReadFile reads a regular file inside the root. Every refusal gives the same message, so that it tells nothing about files outside the root.
func (fr *FilesRoot) ReadFile(field, path string, limit int64) ([]byte, string, error) {
	if fr == nil {
		return nil, "", errNoFilesRoot(field)
	}
	refused := fmt.Errorf("%s: %q is not a regular file inside -files-root", field, path)
	p := strings.TrimSpace(path)
	if p == "" {
		return nil, "", refused
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(fr.dir, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return nil, "", refused
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, "", refused
	}
	rel, err := filepath.Rel(fr.dir, resolved)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "", refused
	}
	if fi, err := fr.root.Lstat(rel); err != nil || !fi.Mode().IsRegular() {
		return nil, "", refused
	}
	f, err := fr.root.Open(rel)
	if err != nil {
		return nil, "", refused
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, "", refused
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, "", fmt.Errorf("%s: reading %q failed", field, path)
	}
	if int64(len(b)) > limit {
		return nil, "", fmt.Errorf("%s: the file is larger than %d bytes", field, limit)
	}
	return b, filepath.Base(abs), nil
}
