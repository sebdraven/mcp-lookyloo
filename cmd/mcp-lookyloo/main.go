// Command mcp-lookyloo serves the Lookyloo REST API over MCP.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
	"github.com/sebdraven/mcp-lookyloo/internal/mcptools"
)

var version = "dev"

func main() {
	var (
		outDir   = flag.String("out", "", "default directory for saved artefacts (screenshots, ZIPs)")
		baseURL  = flag.String("url", "", "Lookyloo instance URL, required (default: $"+lookyloo.EnvURL+")")
		filesDir = flag.String("files-root", "", "directory the *_path parameters may read from; without it they are refused")
		info     = flag.String("info", "", "print the information of one capture and exit")
		urlInfo  = flag.String("url-info", "", "print the captures in which this URL was seen and exit")
		submit   = flag.String("submit", "", "submit one URL (listing off), print its UUID and exit")
		wait     = flag.Bool("wait", false, "with -submit, wait for the capture to finish")
		readOnly = flag.Bool("read-only", false, "register only the read tools (no lk_submit, lk_trigger_modules)")
		push     = flag.Bool("allow-push", false, "also register the tools with effects outside the instance: email report, MISP push, capture upload")
		admin    = flag.Bool("allow-admin", false, "also register the administration tools, lk_admin_remove included")
		addr     = flag.String("http", "", "serve streamable HTTP on this address instead of stdio; no authentication, bind to 127.0.0.1 (e.g. 127.0.0.1:8080)")
		showVer  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	u, err := instanceURL(*baseURL)
	if err != nil {
		log.Fatalf("%v", err)
	}
	var filesRoot *mcptools.FilesRoot
	if strings.TrimSpace(*filesDir) != "" {
		if filesRoot, err = mcptools.NewFilesRoot(*filesDir); err != nil {
			log.Fatalf("%v", err)
		}
	}
	client := lookyloo.New(u, lookyloo.WithVersion(version))
	ctx := context.Background()

	if *info != "" {
		raw, err := client.CaptureInfo(ctx, *info)
		if err != nil {
			log.Fatalf("%v", err)
		}
		printJSON(raw)
		return
	}

	if *urlInfo != "" {
		found, err := client.URLInfo(ctx, *urlInfo, 20, true)
		if err != nil {
			log.Fatalf("%v", err)
		}
		raw, err := json.Marshal(found)
		if err != nil {
			log.Fatalf("encoding the response: %v", err)
		}
		printJSON(raw)
		return
	}

	if *submit != "" {
		id, err := client.Submit(ctx, lookyloo.SubmitParams{URL: *submit})
		if err != nil {
			log.Fatalf("%v", err)
		}
		out := map[string]any{"capture_uuid": id, "outcome": "submitted"}
		if *wait {
			w, err := client.Wait(ctx, id, lookyloo.DefaultWaitTimeout)
			if err != nil {
				log.Fatalf("capture %s: %v", id, err)
			}
			out["outcome"], out["status_code"], out["polls"] = w.Outcome, w.StatusCode, w.Polls
			if w.Error != "" {
				out["capture_error"] = w.Error
			}
		}
		raw, err := json.Marshal(out)
		if err != nil {
			log.Fatalf("encoding the result: %v", err)
		}
		printJSON(raw)
		return
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "lookyloo",
		Version: version,
	}, nil)
	mcptools.Register(server, client, mcptools.Options{
		OutDir:     *outDir,
		FilesRoot:  filesRoot,
		ReadOnly:   *readOnly,
		AllowPush:  *push,
		AllowAdmin: *admin,
	})

	if *addr != "" {
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
		if err := http.ListenAndServe(*addr, handler); err != nil {
			log.Fatalf("http %s: %v", *addr, err)
		}
		return
	}

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func instanceURL(flagValue string) (string, error) {
	u := strings.TrimSpace(flagValue)
	if u == "" {
		u = strings.TrimSpace(os.Getenv(lookyloo.EnvURL))
	}
	if u == "" {
		return "", errors.New("no Lookyloo instance: pass -url https://lookyloo.example.org or set " + lookyloo.EnvURL)
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		return "", fmt.Errorf("instance URL %q: want http(s)://host[:port]", u)
	}
	return u, nil
}

func printJSON(raw json.RawMessage) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		log.Fatalf("formatting the response: %v", err)
	}
	buf.WriteByte('\n')
	os.Stdout.Write(buf.Bytes())
}
