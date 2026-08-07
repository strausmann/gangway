package serve_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/strausmann/gangway/access"
	"github.com/strausmann/gangway/identity/testidp"
	"github.com/strausmann/gangway/serve"
)

// --- helpers shared across this file ---

// noArgs is the input type for the placeholder tools registered below —
// none of them take arguments.
type noArgs struct{}

// syncBuffer is a mutex-guarded bytes.Buffer. The end-to-end tests below
// read the log while a real HTTP server is still handling requests in its
// own goroutine (e.g. a session's final DELETE, or a response still being
// flushed after the client already returned from a call) — a plain
// bytes.Buffer is not safe for that concurrent access.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newServer(t *testing.T, idp *testidp.IDP, logs *syncBuffer) http.Handler {
	t.Helper()

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "160.79.104.0/21")
	t.Setenv("GANGWAY_TRUSTED_PROXIES", "172.16.0.0/12")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	s, err := serve.New(context.Background(), cfg, serve.WithLogWriter(logs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// TestMissingTokenIsUnauthorizedWithChallenge (and every other test
	// sharing this helper) needs an attached MCP handler: Handler only
	// mounts /mcp — and so only reaches the authenticate layer at all —
	// once something has been attached. The handler itself is never
	// exercised by these tests, which never get past the origin gate or
	// the authenticate layer, so a bare 200 stands in for it.
	s.AttachMCP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	return s.Handler()
}

func request(t *testing.T, h http.Handler, remote, forwarded, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	r.RemoteAddr = remote
	if forwarded != "" {
		r.Header.Set("X-Forwarded-For", forwarded)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// bearerRoundTripper injects a bearer token into every outgoing request.
// It exists so the MCP client transport used in the end-to-end tests
// below can authenticate without any of gangway's own code reading or
// touching the token — the transport sends it exactly once, as a header,
// the same way a real connector would.
type bearerRoundTripper struct{ token string }

func (t bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(r)
}

// --- Step 2: the path through all layers ---

func TestUnlistedAddressIsRefusedBeforeAuth(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	// A valid token must not help from an address that is not allowed.
	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	w := request(t, h, "172.20.0.5:5000", "203.0.113.9", token)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestMissingTokenIsUnauthorizedWithChallenge(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	w := request(t, h, "172.20.0.5:5000", "160.79.104.1", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	// Without this header a connector cannot discover where to sign in.
	challenge := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "resource_metadata") {
		t.Errorf("WWW-Authenticate = %q, want a resource_metadata reference", challenge)
	}
	if !strings.Contains(challenge, "https://mcp.example.com") {
		t.Errorf("WWW-Authenticate = %q, want the configured public base URL", challenge)
	}
}

func TestAccessLogRecordsRefusals(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	request(t, h, "172.20.0.5:5000", "203.0.113.9", "")

	if !strings.Contains(logs.String(), " 403 ") {
		t.Errorf("access log %q does not contain the refusal", logs.String())
	}
}

// --- authenticate: the branches TestMissingToken... does not reach ---

func TestAuthenticateRejectsNonBearerAuthorizationHeader(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	r.RemoteAddr = "172.20.0.5:5000"
	r.Header.Set("X-Forwarded-For", "160.79.104.1")
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // not a Bearer token
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthenticateRejectsInvalidToken(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	w := request(t, h, "172.20.0.5:5000", "160.79.104.1", "not-a-real-token")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthenticateAllowsValidTokenAndPublishesIdentity(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "160.79.104.0/21")
	t.Setenv("GANGWAY_TRUSTED_PROXIES", "172.16.0.0/12")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	s, err := serve.New(context.Background(), cfg, serve.WithLogWriter(&logs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var gotSubject string
	var gotOK bool
	s.AttachMCP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := serve.IdentityFrom(r.Context())
		gotOK = ok
		if id != nil {
			gotSubject = id.Subject
		}
		w.WriteHeader(http.StatusOK)
	}))

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-42",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	w := request(t, s.Handler(), "172.20.0.5:5000", "160.79.104.1", token)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !gotOK {
		t.Fatal("IdentityFrom reported no identity for an authenticated request")
	}
	if gotSubject != "user-42" {
		t.Errorf("Subject = %q, want %q", gotSubject, "user-42")
	}
}

func TestIdentityFromReturnsFalseWithoutAnAttachedIdentity(t *testing.T) {
	if id, ok := serve.IdentityFrom(context.Background()); ok || id != nil {
		t.Errorf("IdentityFrom(bare context) = (%v, %v), want (nil, false)", id, ok)
	}
}

// --- Handler: routes reachable without attaching an MCP handler ---

func TestHandlerServesHealthz(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "172.20.0.5:5000"
	r.Header.Set("X-Forwarded-For", "160.79.104.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", w.Body.String(), "ok")
	}
}

func TestHandlerWithoutAttachedMCPHandlerHasNoMCPRoute(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "160.79.104.0/21")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	s, err := serve.New(context.Background(), cfg, serve.WithLogWriter(&logs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Deliberately no AttachMCP call.

	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	r.RemoteAddr = "160.79.104.1:5000"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (no /mcp route mounted)", w.Code, http.StatusNotFound)
	}
}

// --- New: the failure paths a running server must never paper over ---

func TestNewFailsWhenIssuerIsUnreachable(t *testing.T) {
	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	issuerURL := unreachable.URL
	unreachable.Close() // now nothing answers at issuerURL

	cfg := &serve.Config{
		PublicBaseURL:   "https://mcp.example.com",
		IssuerURL:       issuerURL,
		Audience:        "mcp-server",
		SubjectClaim:    "sub",
		AllowedPrefixes: mustPrefixes(t, "160.79.104.0/21"),
	}

	if _, err := serve.New(context.Background(), cfg); err == nil {
		t.Fatal("want an error when the issuer cannot be reached, got none")
	}
}

func TestNewFailsWhenNoAllowlistIsConfigured(t *testing.T) {
	idp := testidp.New(t)

	cfg := &serve.Config{
		PublicBaseURL: "https://mcp.example.com",
		IssuerURL:     idp.URL(),
		Audience:      "mcp-server",
		SubjectClaim:  "sub",
		// Neither AllowedPrefixes nor RemoteListURL is set. LoadConfig
		// refuses this shape already, but New must refuse it too for
		// callers that build a Config by hand.
	}

	_, err := serve.New(context.Background(), cfg)
	if err == nil {
		t.Fatal("want an error when no allowlist is configured, got none")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("error = %q, want it to mention the allowlist", err)
	}
}

func TestNewFailsWhenRemoteAllowlistCannotBeFetched(t *testing.T) {
	idp := testidp.New(t)
	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	listURL := unreachable.URL
	unreachable.Close()

	cfg := &serve.Config{
		PublicBaseURL:      "https://mcp.example.com",
		IssuerURL:          idp.URL(),
		Audience:           "mcp-server",
		SubjectClaim:       "sub",
		RemoteListURL:      listURL,
		RemoteListInterval: time.Hour,
	}

	if _, err := serve.New(context.Background(), cfg); err == nil {
		t.Fatal("want an error when the remote allowlist cannot be fetched, got none")
	}
}

// TestNewSucceedsWithAWorkingRemoteAllowlist covers the success path of
// buildAllowList's remote branch — the failure path is covered by
// TestNewFailsWhenRemoteAllowlistCannotBeFetched above, but that alone
// never proves the fetched list is actually wired into the combined
// allowlist Handler uses. This test does: it configures both a static
// prefix and a remote one, then checks that an address covered only by
// the remote list passes the origin gate.
func TestNewSucceedsWithAWorkingRemoteAllowlist(t *testing.T) {
	idp := testidp.New(t)

	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"}]}`))
	}))
	t.Cleanup(remote.Close)

	cfg := &serve.Config{
		PublicBaseURL:      "https://mcp.example.com",
		IssuerURL:          idp.URL(),
		Audience:           "mcp-server",
		SubjectClaim:       "sub",
		AllowedPrefixes:    mustPrefixes(t, "160.79.104.0/21"), // combined with the remote source below
		RemoteListURL:      remote.URL,
		RemoteListInterval: time.Hour,
	}

	var logs syncBuffer
	gw, err := serve.New(context.Background(), cfg, serve.WithLogWriter(&logs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.AttachMCP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No token is sent: a 401 (reached the authenticate layer) proves the
	// origin gate let the request through; a 403 would mean the remote
	// list never made it into the combined allowlist.
	w := request(t, gw.Handler(), "203.0.113.5:5000", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (remote-listed address should reach the auth layer)", w.Code, http.StatusUnauthorized)
	}
}

func mustPrefixes(t *testing.T, csv ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(csv))
	for _, s := range csv {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parsing test prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

// --- Run: both outcomes of the select in Run ---

func TestRunReturnsAnErrorWhenTheAddressCannotBeBound(t *testing.T) {
	idp := testidp.New(t)

	cfg := &serve.Config{
		Addr:            ":100000", // out of range: net.Listen fails synchronously
		PublicBaseURL:   "https://mcp.example.com",
		IssuerURL:       idp.URL(),
		Audience:        "mcp-server",
		SubjectClaim:    "sub",
		AllowedPrefixes: mustPrefixes(t, "160.79.104.0/21"),
	}
	s, err := serve.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background()) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Run() = nil, want an error for an unbindable address")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return for an address that cannot be bound")
	}
}

func TestRunShutsDownGracefullyWhenContextIsCancelled(t *testing.T) {
	idp := testidp.New(t)

	cfg := &serve.Config{
		Addr:            "127.0.0.1:0", // OS-assigned, never collides
		PublicBaseURL:   "https://mcp.example.com",
		IssuerURL:       idp.URL(),
		Audience:        "mcp-server",
		SubjectClaim:    "sub",
		AllowedPrefixes: mustPrefixes(t, "160.79.104.0/21"),
	}
	s, err := serve.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Give the background goroutine time to reach ListenAndServe's
	// blocking Accept loop before asking it to stop — cancelling before
	// the listener is registered would race Shutdown against Serve's own
	// bookkeeping.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() = %v, want nil after a graceful shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

// --- ToolMiddleware: end-to-end through a real MCP client ---

// newMCPServer builds a *mcp.Server carrying gw's tool-authorization
// middleware and two tools: "read-tool" (classified as reading) and
// "write-tool" (classified as writing). "mystery-tool" is deliberately
// registered but left out of the classification gw was given, to exercise
// the fail-closed default for tools nobody classified.
func newMCPServer(gw *serve.Server) *mcp.Server {
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "gangway-test", Version: "0.0.0"}, nil)

	respond := func(text string) func(context.Context, *mcp.CallToolRequest, noArgs) (*mcp.CallToolResult, any, error) {
		return func(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
		}
	}
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "read-tool"}, respond("read ok"))
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "write-tool"}, respond("write ok"))
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "mystery-tool"}, respond("mystery ok"))

	mcpServer.AddReceivingMiddleware(gw.ToolMiddleware())
	return mcpServer
}

// connectedClient wires gw up to a real HTTP listener, connects an MCP
// client to it over the streamable HTTP transport, and returns the
// session together with everything needed for cleanup and log
// inspection.
func connectedClient(t *testing.T, gw *serve.Server, mcpServer *mcp.Server, token string) *mcp.ClientSession {
	t.Helper()

	gw.AttachMCP(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{Stateless: true},
	))

	ts := httptest.NewServer(gw.Handler())
	t.Cleanup(ts.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "gangway-test-client", Version: "0.0.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: bearerRoundTripper{token: token}},
		DisableStandaloneSSE: true,
	}

	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// TestWriteToolWithoutRoleIsDeniedAtMCPLayer is Task 11's Step 6 test: a
// write tool call from an authenticated caller who holds no writer role
// must be refused as an MCP-level error (not an HTTP error), with the
// refusal visible in the access log.
func TestWriteToolWithoutRoleIsDeniedAtMCPLayer(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "127.0.0.1/32,::1/128")
	// GANGWAY_WRITERS_CLAIM / _VALUE deliberately unset: the default grid
	// then refuses every write, which is exactly the "without the
	// necessary role" case this test is for.

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	gw, err := serve.New(context.Background(), cfg,
		serve.WithLogWriter(&logs),
		serve.WithToolKinds(map[string]access.ToolKind{
			"read-tool":  access.KindRead,
			"write-tool": access.KindWrite,
		}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	session := connectedClient(t, gw, newMCPServer(gw), token)

	_, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "write-tool"})
	if err == nil {
		t.Fatal("CallTool(write-tool) succeeded, want an MCP-level error")
	}

	var wireErr *jsonrpc.Error
	if errors.As(err, &wireErr) {
		if wireErr.Code != serve.CodeForbidden {
			t.Errorf("error code = %d, want %d", wireErr.Code, serve.CodeForbidden)
		}
	} else {
		t.Errorf("error %v does not carry a *jsonrpc.Error", err)
	}

	// The refusal happened inside the MCP layer: the HTTP status of the
	// request that carried it is still 200, and the only place the
	// refusal is visible from the outside is this field.
	if !strings.Contains(logs.String(), `mcp_tool="write-tool" mcp_outcome="denied"`) {
		t.Errorf("access log %q does not record the denial", logs.String())
	}
	if !strings.Contains(logs.String(), ` 200 `) {
		t.Errorf("access log %q does not show HTTP 200 for the refused call", logs.String())
	}
}

// TestReadToolIsAllowedForAnyAuthenticatedCaller complements the denial
// test above: the same caller, with the same lack of any writer role,
// succeeds against a tool classified as reading.
func TestReadToolIsAllowedForAnyAuthenticatedCaller(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "127.0.0.1/32,::1/128")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	gw, err := serve.New(context.Background(), cfg,
		serve.WithLogWriter(&logs),
		serve.WithToolKinds(map[string]access.ToolKind{
			"read-tool":  access.KindRead,
			"write-tool": access.KindWrite,
		}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	session := connectedClient(t, gw, newMCPServer(gw), token)

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "read-tool"})
	if err != nil {
		t.Fatalf("CallTool(read-tool): %v", err)
	}
	if res.IsError {
		t.Errorf("result.IsError = true, want a successful read")
	}

	if !strings.Contains(logs.String(), `mcp_tool="read-tool" mcp_outcome="allowed"`) {
		t.Errorf("access log %q does not record the read as allowed", logs.String())
	}
}

// TestUnclassifiedToolDefaultsToWriteKind proves the fail-closed default
// documented on WithToolKinds: a tool this server never classified is
// refused exactly like a known write tool, not silently let through.
func TestUnclassifiedToolDefaultsToWriteKind(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "127.0.0.1/32,::1/128")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// Deliberately no WithToolKinds: "mystery-tool" (registered by
	// newMCPServer) is never classified.
	gw, err := serve.New(context.Background(), cfg, serve.WithLogWriter(&logs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	session := connectedClient(t, gw, newMCPServer(gw), token)

	_, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "mystery-tool"})
	if err == nil {
		t.Fatal("CallTool(mystery-tool) succeeded, want an MCP-level error (unclassified defaults to write)")
	}
}

// TestOptionsOverrideDefaults exercises WithDecider directly: swapping in
// access.AllowAll must be visible in the ToolMiddleware's behaviour —
// including for a tool that would otherwise be refused by the shipped
// grid.
func TestOptionsOverrideDefaults(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "127.0.0.1/32,::1/128")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	gw, err := serve.New(context.Background(), cfg,
		serve.WithLogWriter(&logs),
		serve.WithDecider(access.AllowAll()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	session := connectedClient(t, gw, newMCPServer(gw), token)

	// write-tool would be refused under the default grid (see
	// TestWriteToolWithoutRoleIsDeniedAtMCPLayer); under AllowAll it must
	// succeed, proving WithDecider's replacement is actually in effect.
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "write-tool"})
	if err != nil {
		t.Fatalf("CallTool(write-tool) under AllowAll: %v", err)
	}
	if res.IsError {
		t.Errorf("result.IsError = true, want AllowAll to permit the call")
	}
}
