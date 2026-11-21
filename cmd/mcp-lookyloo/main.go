// Command mcp-lookyloo serves the Lookyloo REST API over MCP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
)

var version = "dev"

func main() {
	var (
		baseURL = flag.String("url", "", "Lookyloo instance URL (default: $"+lookyloo.EnvURL+", then "+lookyloo.DefaultBaseURL+")")
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

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "lookyloo",
		Version: version,
	}, nil)
	_ = client

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
