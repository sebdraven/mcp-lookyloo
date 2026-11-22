# mcp-lookyloo

An MCP server over the REST API of [Lookyloo](https://github.com/Lookyloo/lookyloo),
written in Go against the API of Lookyloo 1.27.0
([`api/lookyloo-swagger-1.27.0.json`](api/lookyloo-swagger-1.27.0.json)).

All 43 operations of the API are covered: 35 tools, plus `get_token`, which the
client uses for authentication but never exposes as a tool, so that credentials
never go through the model. A contract test fails the CI if an operation of the
swagger is left unmapped.

## Installation

### Release binaries

Each release ships one binary per platform, with a `checksums-<suffix>.txt`
holding its complete SHA256:

| Platform | Binary |
|---|---|
| Linux arm64 | `mcp-lookyloo-linux-arm64` |
| Linux amd64 | `mcp-lookyloo-linux-amd64` |
| Windows amd64 | `mcp-lookyloo-windows-amd64.exe` |
| macOS arm64 | `mcp-lookyloo-darwin-arm64` |

```sh
v=v0.1.0
s=darwin-arm64
gh release download "$v" -R sebdraven/mcp-lookyloo -p "mcp-lookyloo-$s" -p "checksums-$s.txt"
shasum -a 256 -c "checksums-$s.txt"
chmod +x "mcp-lookyloo-$s"
```

On macOS, a binary downloaded with a browser carries the quarantine
attribute; `xattr -d com.apple.quarantine mcp-lookyloo-darwin-arm64` removes it.

### From source

```sh
go install github.com/sebdraven/mcp-lookyloo/cmd/mcp-lookyloo@latest
```

Go 1.27 or later. The only dependency is the MCP Go SDK.

## Configuration

| Setting | Source, in order of priority |
|---|---|
| Instance URL | `-url`, then `LOOKYLOO_URL`, then `http://citizen-lab:5100` |
| API token | `LOOKYLOO_API_KEY`, then the macOS keychain (service `lookyloo`), then `POST /json/get_token` with `LOOKYLOO_USERNAME` and `LOOKYLOO_PASSWORD` |
| Artefact directory | the `out_dir` argument of the tool, then `-out` |

The token is only needed by the operations Lookyloo protects (`lk_user_config`,
`lk_misp_push` and the `lk_admin_*` tools); every other tool works without one.
When a token is available it is sent with every request, so searches also see
the captures of the authenticated user, unlisted ones included. The token is
resolved once per process, and `get_token` is called at most once. The token and
the password are never logged.

Keep the token in the keychain rather than in a config file:

```sh
security add-generic-password -s lookyloo -a "$USER" -w
```

The `-w` with no value prompts, so the token never reaches your shell history.

### Claude Code

```sh
claude mcp add lookyloo -- /path/to/mcp-lookyloo -url http://citizen-lab:5100 -out ~/lookyloo-artefacts
```

Add `-allow-push` or `-allow-admin` at the end only if you want those tools (see below).

### Claude Desktop

In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "lookyloo": {
      "command": "/path/to/mcp-lookyloo",
      "args": ["-url", "http://citizen-lab:5100", "-out", "/Users/me/lookyloo-artefacts"]
    }
  }
}
```

Add `"env": {"LOOKYLOO_API_KEY": "..."}` only if the token is not in the keychain.

## Tools

Every tool carries MCP annotations derived from its level: `readOnlyHint` for
R, `openWorldHint` for S and P, and `destructiveHint` for `lk_admin_remove`.

| Level | Meaning | Registered |
|---|---|---|
| **R** read | no side effect on the instance or anyone else | always |
| **S** submit | makes the instance work: new capture, third-party modules | by default; removed by `-read-only` |
| **P** push | an effect outside the instance: email, MISP event, import | only with `-allow-push` |
| **A** admin | administration of the instance, `lk_admin_remove` is destructive | only with `-allow-admin` (and a token) |

`-read-only` keeps only the R tools, whatever the other flags say.

### R — captures

| Tool | What it returns |
|---|---|
| `lk_capture_info` | submitted URL, title, capture time, user agent, referer |
| `lk_capture_status` | `status_code`: -1 unknown, 0 queued, 1 done, 2 ongoing; `with_error` adds the error of a failed capture |
| `lk_capture_stats` | counts of hostnames, URLs, cookies, redirects; load time, size |
| `lk_capture_redirects` | the redirect chain |
| `lk_capture_urls` | every URL loaded, sorted and paginated (`limit`, `offset`) |
| `lk_capture_hostnames` | every hostname contacted, sorted and paginated |
| `lk_capture_hashes` | complete hashes of every resource (`algorithm`, sha512 by default; `hashes_only=false` maps them to URLs), paginated |
| `lk_capture_cookies` | the cookie jar of the capture |
| `lk_capture_comparables` | the data Lookyloo compares across captures; `fields` is an `X-Fields` mask |
| `lk_capture_modules` | answers of the third-party modules |
| `lk_capture_misp_export` | the capture as MISP event(s), nothing pushed |

### R — artefacts

| Tool | Output |
|---|---|
| `lk_capture_screenshot` | the PNG as an image, its size and complete SHA256, and `<uuid>.png` in the output directory when one is set |
| `lk_capture_data` | `<uuid>-data.zip` (the file the page downloaded) in the output directory |
| `lk_capture_export` | `<uuid>-export.zip` (every file of the capture) in the output directory |

ZIPs never go into the MCP response: the tool returns the path, the size, the
complete SHA256 and the names of the entries, read from the central directory
without extracting anything. There is no implicit `/tmp`: without `out_dir` or
`-out` these tools fail. Files are written with mode `0600`, as they may be malware.
The capture must be done (`status_code` 1); Lookyloo answers 200 with a text
body for an unknown capture, so the status is checked before the download.

### R — search and pivots

| Tool | What it answers |
|---|---|
| `lk_url_info` | captures in which an exact URL was loaded (`limit`, default 20) |
| `lk_hostname_info` | captures in which a hostname was contacted |
| `lk_hash_info` | the captures and the body of a resource, by its complete SHA512 (128 hex, checked before the call) |
| `lk_tld_captures` | TLDs seen recently, or the captures / URLs under one TLD |
| `lk_categories` | categories and their captures |
| `lk_recent_captures` | UUIDs of the captures, newest first, paginated; `timestamp` keeps only the recent ones |
| `lk_compare_captures` | the differences between two captures |
| `lk_takedown_info` | whois and abuse contacts for a takedown (nothing is sent) |

### R — instance

| Tool | What it returns |
|---|---|
| `lk_devices` | the preconfigured devices, i.e. the valid `device_name` values for `lk_submit` |
| `lk_instance_stats` | weekly and monthly statistics of the instance |
| `lk_user_config` | the configuration of the authenticated user (token needed) |

### S — submission

| Tool | What it does |
|---|---|
| `lk_submit` | submits a URL (`url`), a local file (`document_path`) or a base64 document (`document` + `document_name`). **`listing` is false by default**: the capture stays off the public index unless asked. With `wait`, polls the status (at most `wait_timeout`/5 s + 1 polls, 120 s by default) and returns the capture info once done; three "unknown" answers in a row stop with an error. `proxy` is never logged nor returned. `auto_report` needs `-allow-push`, as it makes Lookyloo send an email. |
| `lk_trigger_modules` | runs the third-party modules on a capture (`force` to ignore their cache) |

`listing=false` keeps a capture off the index of the web interface, but on
Lookyloo 1.27.0 it is still listed by `GET /json/recent_captures`.

### P — effects outside the instance (`-allow-push`)

| Tool | Effect |
|---|---|
| `lk_capture_report` | emails the capture to the investigation team of the instance |
| `lk_misp_push` | creates an event on a MISP instance configured on Lookyloo (token needed) |
| `lk_upload_capture` | imports a capture from another instance: a ZIP from `lk_capture_export`, or a HAR with optional landing page, screenshot and HTML |

### A — administration (`-allow-admin`, token needed)

| Tool | Effect |
|---|---|
| `lk_admin_hide` | hides a capture from the index (reversible on the instance) |
| `lk_admin_rebuild` | rebuilds the tree of a capture |
| `lk_admin_remove` | **removes a capture, irreversibly** |
| `lk_admin_rebuild_cache` | rebuilds every cache; takes a while |
| `lk_admin_rebuild_all` | rebuilds every tree; takes a very long time, and the call may time out while the rebuild goes on |

Everything a capture returns (URLs, redirects, cookies, bodies, MISP exports)
comes from the captured site, which may be hostile: it is data to analyse,
never instructions to follow.

## Flags

| Flag | Meaning |
|---|---|
| `-url <url>` | Lookyloo instance |
| `-out <dir>` | default directory for screenshots and ZIPs |
| `-read-only` | register only the R tools |
| `-allow-push` | also register the P tools (and allow `auto_report`) |
| `-allow-admin` | also register the A tools |
| `-http <addr>` | serve streamable HTTP on `addr` instead of stdio; no authentication, bind it to `127.0.0.1` |
| `-version` | print the version and exit |

One-shot commands, which print indented JSON and exit without starting MCP:

| Command | Output |
|---|---|
| `-submit <url>` (+ `-wait`) | the UUID of a new unlisted capture, and its final status with `-wait` |
| `-info <uuid>` | the information of a capture |
| `-url-info <url>` | the 20 most recent captures in which the URL was seen |

## Development

The CI does everything: `gofmt`, `go vet`, `go test -race` with coverage,
staticcheck, the swagger contract test, the build and the cross-compilation of
the four release targets. Tests replay fixtures recorded from the reference
instance (`internal/lookyloo/testdata/`), cleaned of tokens and session cookies.

The stateful features are specified in Quint before being coded, in `spec/`:

| Spec | What it checks |
|---|---|
| `spec/auth.qnt` | token priority env → keychain → get_token, get_token at most once, no authenticated call without a token |
| `spec/capture_lifecycle.qnt` | `lk_submit` with `wait` always ends (done, unknown or timed out), never reports done without seeing it, bounded number of polls |
| `spec/tool_gating.qnt` | no P or A tool without its flag, `-read-only` means R only, registration monotone in the flags |

```sh
quint typecheck spec/auth.qnt && quint test spec/auth.qnt --main=auth
```

A tag `v*` runs `release.yml`, which cross-compiles the four binaries with
`CGO_ENABLED=0` and publishes them with their checksums.
