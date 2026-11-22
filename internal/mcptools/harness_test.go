package mcptools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-lookyloo/internal/lookyloo"
)

const (
	captureUUID = "a222e170-f406-4550-ac25-81bccd02c875"
	unknownUUID = "00000000-0000-4000-8000-000000000000"
)

const pollInterval = 250 * time.Millisecond

type reply struct {
	status  int
	fixture string
	body    string
	ctype   string
	bodies  []string
}

type seen struct {
	method string
	path   string
	query  string
	header http.Header
	body   []byte
}

type fake struct {
	t      *testing.T
	mu     sync.Mutex
	routes map[string]reply
	calls  []seen
	served map[string]int
}

func newFake(t *testing.T, routes map[string]reply) *fake {
	return &fake{t: t, routes: routes, served: map[string]int{}}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "lookyloo", "testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, seen{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, header: r.Header.Clone(), body: body})
	key := r.Method + " " + r.URL.Path
	rep, ok := f.routes[key]
	n := f.served[key]
	f.served[key]++
	f.mu.Unlock()
	if !ok {
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		http.NotFound(w, r)
		return
	}
	b := []byte(rep.body)
	if len(rep.bodies) > 0 {
		b = []byte(rep.bodies[min(n, len(rep.bodies)-1)])
	}
	if rep.fixture != "" {
		b = readFixture(f.t, rep.fixture)
	}
	ctype := rep.ctype
	if ctype == "" {
		ctype = "application/json"
	}
	w.Header().Set("Content-Type", ctype)
	status := rep.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	w.Write(b)
}

func (f *fake) requests() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seen(nil), f.calls...)
}

type env struct {
	fake    *fake
	session *mcp.ClientSession
	names   []string
}

func start(t *testing.T, routes map[string]reply, token string, opts Options) *env {
	t.Helper()
	f := newFake(t, routes)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	c := lookyloo.New(srv.URL, lookyloo.WithTokenSource(lookyloo.StaticToken(token)), lookyloo.WithPollInterval(pollInterval))
	s := mcp.NewServer(&mcp.Implementation{Name: "lookyloo", Version: "test"}, nil)
	names := Register(s, c, opts)

	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() {
		cs.Close()
		ss.Close()
	})
	return &env{fake: f, session: cs, names: names}
}

func (e *env) call(t *testing.T, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := e.session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func decode(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", text(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decoding %s: %v", b, err)
	}
}
