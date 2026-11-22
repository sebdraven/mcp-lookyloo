package mcptools

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
)

const maxUploadBytes = 512 << 20

type reportInput struct {
	CaptureUUID string `json:"capture_uuid" jsonschema:"UUID of the capture to report"`
	Email       string `json:"email,omitempty" jsonschema:"email of the reporter, for the analyst to get in touch"`
	Comment     string `json:"comment,omitempty" jsonschema:"description of the URL for the analyst"`
}

type mispPushInput struct {
	CaptureUUID     string `json:"capture_uuid" jsonschema:"UUID of the capture to push"`
	InstanceName    string `json:"instance_name,omitempty" jsonschema:"MISP instance configured on Lookyloo (default: its default instance)"`
	AllowDuplicates bool   `json:"allow_duplicates,omitempty" jsonschema:"push even if the event already exists on MISP"`
	WithParents     bool   `json:"with_parents,omitempty" jsonschema:"also push the parent captures, if any"`
}

type uploadInput struct {
	FullCapturePath string `json:"full_capture_path,omitempty" jsonschema:"ZIP from lk_capture_export of another instance, relative to or inside -files-root; give exactly one of full_capture_path, full_capture, har_file_path, har_file"`
	FullCapture     string `json:"full_capture,omitempty" jsonschema:"base64 of such a ZIP"`
	HARFilePath     string `json:"har_file_path,omitempty" jsonschema:"HAR file, plain JSON or gzip, relative to or inside -files-root"`
	HARFile         string `json:"har_file,omitempty" jsonschema:"base64 of a HAR file, plain JSON or gzip"`
	LandingPage     string `json:"landing_page,omitempty" jsonschema:"with a HAR: the URL the capture ended on"`
	ScreenshotPath  string `json:"screenshot_path,omitempty" jsonschema:"with a HAR: PNG screenshot, relative to or inside -files-root"`
	HTMLPath        string `json:"html_path,omitempty" jsonschema:"with a HAR: HTML of the landing page, relative to or inside -files-root"`
	Listing         bool   `json:"listing,omitempty" jsonschema:"show the imported capture on the web index (default false); false does not make it private, it stays listed by the recent_captures API"`
}

func (r *registry) pushTools(s *mcp.Server) {
	addTool(r, s, &mcp.Tool{
		Name: "lk_capture_report",
		Description: "Report a capture: Lookyloo SENDS AN EMAIL to the investigation team of the instance with the capture, email and comment. " +
			"Only registered with -allow-push.",
	}, r.report)

	addTool(r, s, &mcp.Tool{
		Name: "lk_misp_push",
		Description: "CREATE AN EVENT on a MISP instance configured on Lookyloo from the capture (see lk_capture_misp_export for a dry run). " +
			"Needs an API token. Only registered with -allow-push.",
	}, r.mispPush)

	addTool(r, s, &mcp.Tool{
		Name: "lk_upload_capture",
		Description: "Import into this instance a capture made elsewhere: a full ZIP export, or a HAR file with optional landing page, screenshot and HTML. " +
			"Returns the UUID of the new capture, unlisted unless listing is true; listing=false only hides it from the web index, it stays visible to anyone through the recent_captures API of the instance, so never upload anything confidential to a shared instance. " +
			"Paths are read only inside -files-root. Only registered with -allow-push.",
	}, r.upload)
}

func (r *registry) report(ctx context.Context, _ *mcp.CallToolRequest, in reportInput) (*mcp.CallToolResult, any, error) {
	raw, err := r.client.CaptureReport(ctx, in.CaptureUUID, in.Email, in.Comment)
	if err != nil {
		return nil, nil, captureErr(err)
	}
	return rawResult(raw), nil, nil
}

func (r *registry) mispPush(ctx context.Context, _ *mcp.CallToolRequest, in mispPushInput) (*mcp.CallToolResult, any, error) {
	raw, err := r.client.MISPPush(ctx, in.CaptureUUID, in.InstanceName, in.AllowDuplicates, in.WithParents)
	if err != nil {
		return nil, nil, captureErr(err)
	}
	return rawResult(raw), nil, nil
}

func (r *registry) readLocal(field, path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	b, _, err := r.opts.FilesRoot.ReadFile(field, path, maxUploadBytes)
	return b, err
}

func decodeB64(field, s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64", field)
	}
	return b, nil
}

func (r *registry) upload(ctx context.Context, _ *mcp.CallToolRequest, in uploadInput) (*mcp.CallToolResult, lookyloo.UploadResult, error) {
	sources := 0
	for _, v := range []string{in.FullCapturePath, in.FullCapture, in.HARFilePath, in.HARFile} {
		if strings.TrimSpace(v) != "" {
			sources++
		}
	}
	if sources != 1 {
		return nil, lookyloo.UploadResult{}, errors.New("give exactly one of full_capture_path, full_capture, har_file_path or har_file")
	}
	p := lookyloo.UploadParams{Listing: in.Listing, LandingPage: in.LandingPage}
	steps := []struct {
		dst  *[]byte
		load func() ([]byte, error)
	}{
		{&p.FullCapture, func() ([]byte, error) { return r.readLocal("full_capture_path", in.FullCapturePath) }},
		{&p.FullCapture, func() ([]byte, error) { return decodeB64("full_capture", in.FullCapture) }},
		{&p.HAR, func() ([]byte, error) { return r.readLocal("har_file_path", in.HARFilePath) }},
		{&p.HAR, func() ([]byte, error) { return decodeB64("har_file", in.HARFile) }},
		{&p.Screenshot, func() ([]byte, error) { return r.readLocal("screenshot_path", in.ScreenshotPath) }},
		{&p.HTML, func() ([]byte, error) { return r.readLocal("html_path", in.HTMLPath) }},
	}
	for _, st := range steps {
		b, err := st.load()
		if err != nil {
			return nil, lookyloo.UploadResult{}, err
		}
		if b != nil {
			*st.dst = b
		}
	}
	res, err := r.client.UploadCapture(ctx, p)
	if err != nil {
		return nil, lookyloo.UploadResult{}, err
	}
	return nil, res, nil
}
