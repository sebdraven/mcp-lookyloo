package mcptools

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
)

const maxListedEntries = 200

type artefactInput struct {
	CaptureUUID string `json:"capture_uuid" jsonschema:"UUID of the capture"`
	OutDir      string `json:"out_dir,omitempty" jsonschema:"directory to write the file into (default: the server's -out)"`
}

type screenshotOutput struct {
	CaptureUUID string `json:"capture_uuid"`
	Size        int    `json:"size"`
	SHA256      string `json:"sha256"`
	Path        string `json:"path,omitempty"`
}

type zipEntry struct {
	Name string `json:"name"`
	Size uint64 `json:"size"`
}

type archiveOutput struct {
	CaptureUUID      string     `json:"capture_uuid"`
	Path             string     `json:"path"`
	Size             int64      `json:"size"`
	SHA256           string     `json:"sha256"`
	Entries          []zipEntry `json:"entries"`
	EntriesTruncated bool       `json:"entries_truncated,omitempty"`
}

func (r *registry) dir(override string) string {
	if d := strings.TrimSpace(override); d != "" {
		return d
	}
	return strings.TrimSpace(r.opts.OutDir)
}

func (r *registry) artefactTools(s *mcp.Server) {
	addTool(r, s, &mcp.Tool{
		Name: "lk_capture_screenshot",
		Description: "The PNG screenshot of a capture, returned as an image, with its size and complete SHA256. " +
			"When out_dir (or the server's -out) is set it is also written there as <uuid>.png. The capture must be done.",
	}, r.screenshot)

	addTool(r, s, &mcp.Tool{
		Name: "lk_capture_data",
		Description: "The file the capture downloaded, as the ZIP Lookyloo builds, written to out_dir (or the server's -out) as <uuid>-data.zip. " +
			"Only the path, size, complete SHA256 and the entry names are returned; the archive is never extracted. " +
			"A single entry named no_download means the page triggered no download. The content may be malware.",
	}, r.archive(r.client.SaveData))

	addTool(r, s, &mcp.Tool{
		Name: "lk_capture_export",
		Description: "Every file the capture produced (HAR, HTML, screenshot, DNS data, settings) as a ZIP, written to out_dir (or the server's -out) as <uuid>-export.zip. " +
			"Only the path, size, complete SHA256 and the entry names are returned; the archive is never extracted.",
	}, r.archive(r.client.SaveExport))
}

func (r *registry) screenshot(ctx context.Context, _ *mcp.CallToolRequest, in artefactInput) (*mcp.CallToolResult, screenshotOutput, error) {
	png, err := r.client.Screenshot(ctx, in.CaptureUUID)
	if err != nil {
		return nil, screenshotOutput{}, err
	}
	id, _ := lookyloo.NormaliseUUID(in.CaptureUUID)
	sum := sha256.Sum256(png)
	out := screenshotOutput{CaptureUUID: id, Size: len(png), SHA256: hex.EncodeToString(sum[:])}
	if dir := r.dir(in.OutDir); dir != "" {
		a, err := lookyloo.SaveFile(dir, id+".png", png)
		if err != nil {
			return nil, screenshotOutput{}, err
		}
		out.Path = a.Path
	}
	res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.ImageContent{Data: png, MIMEType: "image/png"}}}
	return res, out, nil
}

type saveFunc func(ctx context.Context, uuid, dir string) (lookyloo.Artefact, error)

func (r *registry) archive(save saveFunc) mcp.ToolHandlerFor[artefactInput, archiveOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in artefactInput) (*mcp.CallToolResult, archiveOutput, error) {
		a, err := save(ctx, in.CaptureUUID, r.dir(in.OutDir))
		if err != nil {
			return nil, archiveOutput{}, err
		}
		id, _ := lookyloo.NormaliseUUID(in.CaptureUUID)
		out := archiveOutput{CaptureUUID: id, Path: a.Path, Size: a.Size, SHA256: a.SHA256}
		out.Entries, out.EntriesTruncated = listEntries(a.Path)
		return nil, out, nil
	}
}

func listEntries(path string) ([]zipEntry, bool) {
	entries := []zipEntry{}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return entries, false
	}
	defer zr.Close()
	for i, f := range zr.File {
		if i == maxListedEntries {
			return entries, true
		}
		entries = append(entries, zipEntry{Name: f.Name, Size: f.UncompressedSize64})
	}
	return entries, false
}
