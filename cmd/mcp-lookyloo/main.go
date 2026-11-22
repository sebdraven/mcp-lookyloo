// Command mcp-lookyloo serves the Lookyloo REST API over MCP.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
	"github.com/sebdraven/mcp-lookyloo/internal/mcptools"
)

var version = "dev"

func main() {
	var (
		baseURL = flag.String("url", "", "Lookyloo instance URL (default: $"+lookyloo.EnvURL+", then "+lookyloo.DefaultBaseURL+")")
		info    = flag.String("info", "", "print the information of one capture and exit")
		urlInfo = flag.String("url-info", "", "print the captures in which this URL was seen and exit")
		addr    = flag.String("http", "", "serve streamable HTTP on this address instead of stdio; no authentication, bind to 127.0.0.1 (e.g. 127.0.0.1:8080)")
		showVer = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	client := lookyloo.New(instanceURL(*baseURL), lookyloo.WithVersion(version))
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

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "lookyloo",
		Version: version,
	}, nil)
	mcptools.Register(server, client, mcptools.Options{})

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

func instanceURL(flagValue string) string {
	if u := strings.TrimSpace(flagValue); u != "" {
		return u
	}
	if u := strings.TrimSpace(os.Getenv(lookyloo.EnvURL)); u != "" {
		return u
	}
	return lookyloo.DefaultBaseURL
}

func printJSON(raw json.RawMessage) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		log.Fatalf("formatting the response: %v", err)
	}
	buf.WriteByte('\n')
	os.Stdout.Write(buf.Bytes())
}
