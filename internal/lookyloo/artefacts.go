package lookyloo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxScreenshotBytes = 64 << 20
	maxArchiveBytes    = 2 << 30
)

var (
	pngMagic = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	zipMagic = []byte{'P', 'K', 0x03, 0x04}
)

var ErrNoOutDir = errors.New("no output directory: pass out_dir, or start the server with -out <dir>")

type Artefact struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Lookyloo serves its "not available" text with a 200 and the artefact's MIME type, so the capture must be done first.
func (c *Client) ensureDone(ctx context.Context, uuid string) (string, error) {
	id, err := NormaliseUUID(uuid)
	if err != nil {
		return "", err
	}
	st, err := c.CaptureStatus(ctx, id, false)
	if err != nil {
		return "", err
	}
	switch st.StatusCode {
	case StatusDone:
		return id, nil
	case StatusUnknown:
		return "", fmt.Errorf("lookyloo: capture %s is unknown to the instance", id)
	default:
		return "", fmt.Errorf("lookyloo: capture %s is not done yet (status %d); retry once lk_capture_status reports 1", id, st.StatusCode)
	}
}

func (c *Client) Screenshot(ctx context.Context, uuid string) ([]byte, error) {
	id, err := c.ensureDone(ctx, uuid)
	if err != nil {
		return nil, err
	}
	path := "/bin/" + id + "/screenshot"
	resp, err := c.do(ctx, request{method: http.MethodGet, path: path, auth: authOptional, bulk: true})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxScreenshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("lookyloo GET %s: %w", path, err)
	}
	if len(b) > maxScreenshotBytes {
		return nil, fmt.Errorf("lookyloo GET %s: the screenshot is larger than %d bytes", path, maxScreenshotBytes)
	}
	if !bytes.HasPrefix(b, pngMagic) {
		return nil, fmt.Errorf("lookyloo GET %s: the response is not a PNG: %s", path, truncate(string(b), 200))
	}
	return b, nil
}

func (c *Client) SaveData(ctx context.Context, uuid, dir string) (Artefact, error) {
	return c.saveArchive(ctx, uuid, dir, "data")
}

func (c *Client) SaveExport(ctx context.Context, uuid, dir string) (Artefact, error) {
	return c.saveArchive(ctx, uuid, dir, "export")
}

func (c *Client) saveArchive(ctx context.Context, uuid, dir, kind string) (Artefact, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return Artefact{}, ErrNoOutDir
	}
	id, err := c.ensureDone(ctx, uuid)
	if err != nil {
		return Artefact{}, err
	}
	path := "/bin/" + id + "/" + kind
	resp, err := c.do(ctx, request{method: http.MethodGet, path: path, auth: authOptional, bulk: true})
	if err != nil {
		return Artefact{}, err
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	head, _ := br.Peek(len(zipMagic))
	if !bytes.Equal(head, zipMagic) {
		peek, _ := br.Peek(200)
		return Artefact{}, fmt.Errorf("lookyloo GET %s: the response is not a ZIP: %s", path, string(peek))
	}
	return writeAtomically(dir, id+"-"+kind+".zip", br, maxArchiveBytes)
}

func writeAtomically(dir, name string, r io.Reader, max int64) (Artefact, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Artefact{}, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return Artefact{}, fmt.Errorf("creating %s: %w", abs, err)
	}
	tmp, err := os.CreateTemp(abs, "."+name+".*.part")
	if err != nil {
		return Artefact{}, fmt.Errorf("writing into %s: %w", abs, err)
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("the artefact is larger than %d bytes", max)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o600)
	}
	final := filepath.Join(abs, name)
	if err == nil {
		err = os.Rename(tmp.Name(), final)
	}
	if err != nil {
		return Artefact{}, fmt.Errorf("writing %s: %w", final, err)
	}
	return Artefact{Path: final, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func SaveFile(dir, name string, b []byte) (Artefact, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return Artefact{}, ErrNoOutDir
	}
	return writeAtomically(dir, name, bytes.NewReader(b), int64(len(b)))
}
