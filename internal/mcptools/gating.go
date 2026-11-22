package mcptools

import "github.com/modelcontextprotocol/go-sdk/mcp"

// Level is the permission level of a tool (SPEC §0); spec/tool_gating.qnt models the gating.
type Level int

const (
	Read Level = iota
	Submit
	Push
	Admin
)

func (l Level) String() string {
	return [...]string{"R", "S", "P", "A"}[l]
}

// ToolLevels is the level of every tool; Register refuses a tool missing from it.
var ToolLevels = map[string]Level{
	"lk_capture_info":        Read,
	"lk_capture_status":      Read,
	"lk_capture_stats":       Read,
	"lk_capture_redirects":   Read,
	"lk_capture_urls":        Read,
	"lk_capture_hostnames":   Read,
	"lk_capture_hashes":      Read,
	"lk_capture_cookies":     Read,
	"lk_capture_comparables": Read,
	"lk_capture_modules":     Read,
	"lk_capture_misp_export": Read,
	"lk_capture_screenshot":  Read,
	"lk_capture_data":        Read,
	"lk_capture_export":      Read,
	"lk_url_info":            Read,
	"lk_hostname_info":       Read,
	"lk_hash_info":           Read,
	"lk_tld_captures":        Read,
	"lk_categories":          Read,
	"lk_recent_captures":     Read,
	"lk_compare_captures":    Read,
	"lk_takedown_info":       Read,
	"lk_devices":             Read,
	"lk_instance_stats":      Read,
	"lk_user_config":         Read,
	"lk_submit":              Submit,
	"lk_trigger_modules":     Submit,
	"lk_capture_report":      Push,
	"lk_misp_push":           Push,
	"lk_upload_capture":      Push,
	"lk_admin_hide":          Admin,
	"lk_admin_rebuild":       Admin,
	"lk_admin_remove":        Admin,
	"lk_admin_rebuild_cache": Admin,
	"lk_admin_rebuild_all":   Admin,
}

var destructive = map[string]bool{"lk_admin_remove": true}

func (o Options) allows(l Level) bool {
	switch l {
	case Read:
		return true
	case Submit:
		return !o.ReadOnly
	case Push:
		return !o.ReadOnly && o.AllowPush
	case Admin:
		return !o.ReadOnly && o.AllowAdmin
	}
	return false
}

func annotations(name string, l Level) *mcp.ToolAnnotations {
	switch l {
	case Read:
		return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)}
	case Submit, Push:
		return &mcp.ToolAnnotations{OpenWorldHint: new(true), DestructiveHint: new(false)}
	default:
		return &mcp.ToolAnnotations{OpenWorldHint: new(false), DestructiveHint: new(destructive[name])}
	}
}
