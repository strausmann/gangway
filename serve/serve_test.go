package serve_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/strausmann/gangway/access"
	"github.com/strausmann/gangway/accesslog"
	"github.com/strausmann/gangway/backend"
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

// waitForLogLine polls logs until it contains want or the timeout
// elapses, returning whatever the buffer held at that point either way.
//
// The access log line for an end-to-end MCP call is written by the
// server's own connection-handling goroutine, strictly after it finishes
// writing the HTTP response — but the client can observe that same
// response as complete, and return from CallTool, a few instructions
// earlier: TCP delivery to the client's kernel does not wait for the
// server-side handler to finish its own bookkeeping. A single immediate
// check right after CallTool returns is therefore flaky (observed: about
// 1 run in 15); polling with a short bound is not.
func waitForLogLine(logs *syncBuffer, want string) string {
	deadline := time.Now().Add(2 * time.Second)
	var last string
	for {
		last = logs.String()
		if strings.Contains(last, want) || time.Now().After(deadline) {
			return last
		}
		time.Sleep(5 * time.Millisecond)
	}
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
	// once something has been attached. The server itself is never
	// exercised by these tests, which never get past the origin gate or
	// the authenticate layer, so an empty stub stands in for it.
	s.AttachMCP(stubMCPServer())
	return s.Handler()
}

// stubMCPServer returns a bare *mcp.Server with no tools registered, for
// tests that only exercise the HTTP layers (origin gate, authenticate)
// and never reach the MCP server itself.
func stubMCPServer() *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{Name: "gangway-test-stub", Version: "0.0.0"}, nil)
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

// TestOriginRefusalLogLineEscapesForgedNewline is the regression test for
// the log-forging finding in the origin gate's rejection hook: r.URL.Path
// is decoded, attacker-controlled input, and a request whose path decodes
// to contain a newline must not be able to split that hook's log line in
// two — the second half, unescaped, would read as a second, fabricated
// log line, forgeable to any address and status the attacker chooses.
func TestOriginRefusalLogLineEscapesForgedNewline(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	r := httptest.NewRequest(http.MethodGet, "/x%0Afake-line", nil)
	r.RemoteAddr = "172.20.0.5:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.9") // not in the allowlist
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	// Exactly two lines are expected for this one request: the raw
	// origin-refusal line, and accesslog.Middleware's own combined-format
	// line for the same (403) response. A decoded, unescaped newline in
	// the path would add a third.
	trimmed := strings.TrimRight(logs.String(), "\n")
	lines := strings.Split(trimmed, "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d log lines for one refused request, want exactly 2: %q", len(lines), logs.String())
	}
	if !strings.Contains(lines[0], accesslog.EscapeField("/x\nfake-line")) {
		t.Errorf("origin-refusal line = %q, want the escaped path %q", lines[0], accesslog.EscapeField("/x\nfake-line"))
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

// TestAuthenticateAllowsValidTokenAndPublishesIdentity checks identity
// propagation end-to-end through a real MCP client: "whoami-tool" (see
// newMCPServer) reports back whatever IdentityFrom(ctx) sees inside the
// tool-authorization middleware and the tool handler, which is the only
// way this is observable from outside now that AttachMCP builds the
// handler itself — there is no longer a way to attach a bare
// http.HandlerFunc that reads the context directly.
func TestAuthenticateAllowsValidTokenAndPublishesIdentity(t *testing.T) {
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
		serve.WithToolKinds(map[string]access.ToolKind{"whoami-tool": access.KindRead}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-42",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	session := connectedClient(t, gw, newMCPServer(), token)

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "whoami-tool"})
	if err != nil {
		t.Fatalf("CallTool(whoami-tool): %v", err)
	}
	if res.IsError {
		t.Fatalf("result.IsError = true, want a successful call: %+v", res.Content)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] = %T, want *mcp.TextContent", res.Content[0])
	}
	if text.Text != "user-42" {
		t.Errorf("whoami-tool reported %q, want the authenticated subject %q", text.Text, "user-42")
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

// TestHealthzIsReachableFromAnUnlistedAddress is the direct proof of the
// health-endpoint's deliberate exemption from the origin gate: an
// address that appears nowhere in the connector allowlist can still
// reach /healthz — a liveness probe does not run from a connector
// address (see Handler). The request must still show up in the access
// log (checked here too): the exemption is from the origin gate, not
// from being recorded.
func TestHealthzIsReachableFromAnUnlistedAddress(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "172.20.0.5:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.9") // nowhere in the allowlist
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d — an unlisted address must still reach /healthz", w.Code, http.StatusOK)
	}
	// Nothing but reachability: no version, no configuration, no
	// counters — anything more here would be a second, silent way for
	// this deliberately open endpoint to leak information to an address
	// the origin gate would otherwise have kept out entirely.
	if w.Body.String() != "ok" {
		t.Errorf("body = %q, want exactly %q", w.Body.String(), "ok")
	}
	if !strings.Contains(logs.String(), `"GET /healthz HTTP/1.1" 200`) {
		t.Errorf("access log %q does not record the health check", logs.String())
	}
}

// TestMCPStillRejectsTheSameUnlistedAddress is the more important half
// of the health-endpoint exception's proof: the exact address that just
// reached /healthz above must still be refused by /mcp. Without this
// test, a change that accidentally widened the exemption — moving
// /healthz's bypass up a level, say, so it covered the whole mux instead
// of one path — would look identical to the intended fix: /healthz
// still returns 200. This is what would actually catch it.
func TestMCPStillRejectsTheSameUnlistedAddress(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	w := request(t, h, "172.20.0.5:5000", "203.0.113.9", token)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d — the health-endpoint exception must not extend to /mcp, even with a valid token", w.Code, http.StatusForbidden)
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
	gw.AttachMCP(stubMCPServer())

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

// --- tool authorization: end-to-end through a real MCP client ---

// newMCPServer builds a bare *mcp.Server with four tools: "read-tool"
// (classified as reading by the tests that use it), "write-tool"
// (classified as writing), "mystery-tool" (deliberately left out of
// every classification, to exercise the fail-closed default for tools
// nobody classified), and "whoami-tool" (reports the caller's identity
// via IdentityFrom, for tests that check identity propagation).
//
// It does not touch tool-authorization middleware or build any HTTP
// handler — AttachMCP owns both of those now, and does them for whatever
// *mcp.Server it is given. Registering tools here and authorizing them
// are deliberately two different servers' jobs: what newMCPServer builds
// could equally well be served over stdio, with no gangway involved at
// all.
func newMCPServer() *mcp.Server {
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "gangway-test", Version: "0.0.0"}, nil)

	respond := func(text string) func(context.Context, *mcp.CallToolRequest, noArgs) (*mcp.CallToolResult, any, error) {
		return func(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
		}
	}
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "read-tool"}, respond("read ok"))
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "write-tool"}, respond("write ok"))
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "mystery-tool"}, respond("mystery ok"))
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "whoami-tool"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
			id, ok := serve.IdentityFrom(ctx)
			if !ok {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "no identity"}}}, nil, nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: id.Subject}}}, nil, nil
		})
	// Exercises backend.PassThrough exactly the way a real tool would:
	// pull the incoming token out of the context via TokenFrom and hand
	// it to TokenFor. Without TokenFrom, incoming is always "" and
	// PassThrough refuses outright — this tool is the proof that the
	// context plumbing actually delivers a usable token, not just that
	// something is present in the context.
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "passthrough-tool"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
			id, _ := serve.IdentityFrom(ctx)
			incoming, _ := serve.TokenFrom(ctx)
			tok, err := backend.PassThrough().TokenFor(ctx, id, incoming)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: tok}}}, nil, nil
		})

	return mcpServer
}

// connectedClient attaches mcpServer to gw (AttachMCP installs the
// tool-authorization middleware and builds the stateless HTTP handler),
// serves it on a real HTTP listener, connects an MCP client to it over
// the streamable HTTP transport, and returns the session together with
// everything needed for cleanup and log inspection.
func connectedClient(t *testing.T, gw *serve.Server, mcpServer *mcp.Server, token string) *mcp.ClientSession {
	t.Helper()

	gw.AttachMCP(mcpServer)

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
	session := connectedClient(t, gw, newMCPServer(), token)

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
	line := waitForLogLine(&logs, `mcp_tool="write-tool" mcp_outcome="denied"`)
	if !strings.Contains(line, `mcp_tool="write-tool" mcp_outcome="denied"`) {
		t.Errorf("access log %q does not record the denial", line)
	}
	if !strings.Contains(line, ` 200 `) {
		t.Errorf("access log %q does not show HTTP 200 for the refused call", line)
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
	session := connectedClient(t, gw, newMCPServer(), token)

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "read-tool"})
	if err != nil {
		t.Fatalf("CallTool(read-tool): %v", err)
	}
	if res.IsError {
		t.Errorf("result.IsError = true, want a successful read")
	}

	line := waitForLogLine(&logs, `mcp_tool="read-tool" mcp_outcome="allowed"`)
	if !strings.Contains(line, `mcp_tool="read-tool" mcp_outcome="allowed"`) {
		t.Errorf("access log %q does not record the read as allowed", line)
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
	session := connectedClient(t, gw, newMCPServer(), token)

	_, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "mystery-tool"})
	if err == nil {
		t.Fatal("CallTool(mystery-tool) succeeded, want an MCP-level error (unclassified defaults to write)")
	}
}

// TestPassThroughReceivesTheIncomingToken is the end-to-end proof that
// TokenFrom actually delivers a usable token to backend.PassThrough — not
// just that a value sits in the context, but that a tool built on
// PassThrough works: the incoming HTTP bearer token authenticates the
// call, reaches the tool handler via TokenFrom, and comes back out of
// backend.PassThrough().TokenFor unchanged.
func TestPassThroughReceivesTheIncomingToken(t *testing.T) {
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
		serve.WithToolKinds(map[string]access.ToolKind{"passthrough-tool": access.KindRead}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	session := connectedClient(t, gw, newMCPServer(), token)

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "passthrough-tool"})
	if err != nil {
		t.Fatalf("CallTool(passthrough-tool): %v", err)
	}
	if res.IsError {
		t.Fatalf("result.IsError = true, want the tool to receive the incoming token: %+v", res.Content)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] = %T, want *mcp.TextContent", res.Content[0])
	}
	if text.Text != token {
		t.Errorf("backend.PassThrough forwarded a different token than the one used to authenticate the call")
	}
}

// TestOptionsOverrideDefaults exercises WithDecider directly: swapping in
// access.AllowAll must be visible in the tool-authorization middleware's
// behaviour — including for a tool that would otherwise be refused by
// the shipped grid.
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
	session := connectedClient(t, gw, newMCPServer(), token)

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

// --- discovery: the reference a 401 hands out must actually resolve ---

// TestChallengePointsToAFetchableMetadataDocument is the regression test
// for the discovery-loop finding: a connector following RFC 9728 fetches
// the WWW-Authenticate challenge's resource_metadata URL before it has a
// token. This test does exactly that — literally follows the URL out of
// the header, unmodified — rather than asserting anything about the route
// directly, so it fails the same way a real connector would if the route
// were missing, gated behind authenticate (a loop with no way out), or
// pointed at the wrong address.
func TestChallengePointsToAFetchableMetadataDocument(t *testing.T) {
	idp := testidp.New(t)

	// The listener has to exist before Config.Handler can be attached,
	// but PublicBaseURL — which the challenge's resource_metadata URL is
	// built from — has to name this listener's own address, or the
	// fetch below would go nowhere. NewUnstartedServer breaks that
	// chicken-and-egg problem: the listener (and so its address) exists
	// before Start is called.
	ts := httptest.NewUnstartedServer(nil)
	publicBaseURL := "http://" + ts.Listener.Addr().String()

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", publicBaseURL)
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "127.0.0.1/32,::1/128")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	var logs syncBuffer
	gw, err := serve.New(context.Background(), cfg, serve.WithLogWriter(&logs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.AttachMCP(stubMCPServer())

	ts.Config.Handler = gw.Handler()
	ts.Start()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp")
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /mcp = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	challenge := resp.Header.Get("WWW-Authenticate")
	_, rest, ok := strings.Cut(challenge, `resource_metadata="`)
	if !ok {
		t.Fatalf("WWW-Authenticate = %q, no resource_metadata reference found", challenge)
	}
	metadataURL, _, ok := strings.Cut(rest, `"`)
	if !ok {
		t.Fatalf("WWW-Authenticate = %q, resource_metadata value not terminated", challenge)
	}

	mresp, err := http.Get(metadataURL)
	if err != nil {
		t.Fatalf("GET %s (the URL the 401 itself handed out): %v", metadataURL, err)
	}
	defer func() { _ = mresp.Body.Close() }()
	if mresp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want %d", metadataURL, mresp.StatusCode, http.StatusOK)
	}

	var doc oauthex.ProtectedResourceMetadata
	if err := json.NewDecoder(mresp.Body).Decode(&doc); err != nil {
		t.Fatalf("resource metadata document at %s is not valid JSON: %v", metadataURL, err)
	}
	if doc.Resource != publicBaseURL {
		t.Errorf("Resource = %q, want %q", doc.Resource, publicBaseURL)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != idp.URL() {
		t.Errorf("AuthorizationServers = %v, want [%q]", doc.AuthorizationServers, idp.URL())
	}
}

// --- WithLogWriter: the writer need not be safe for concurrent use ---

// TestLogWriterNeedNotBeConcurrencySafe reproduces the review finding
// directly: a plain bytes.Buffer — not safe for concurrent use on its own
// — handed to WithLogWriter, hit by concurrent requests that exercise
// both call sites writing into it (accesslog.Middleware, once per
// request, and the origin gate's rejection hook, for the refused half).
// Run under -race, this fails immediately if New ever stops wrapping the
// configured writer in something that serializes access to it.
func TestLogWriterNeedNotBeConcurrencySafe(t *testing.T) {
	idp := testidp.New(t)

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "160.79.104.0/21")
	t.Setenv("GANGWAY_TRUSTED_PROXIES", "127.0.0.1/32")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	var buf bytes.Buffer // deliberately not this file's syncBuffer
	gw, err := serve.New(context.Background(), cfg, serve.WithLogWriter(&buf))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.AttachMCP(stubMCPServer())

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(refused bool) {
			defer wg.Done()
			// /healthz bypasses the origin gate entirely (see Handler),
			// so it can no longer exercise the OnReject write path —
			// target /mcp for the refused half instead, which stays
			// behind the gate.
			target := ts.URL + "/healthz"
			if refused {
				target = ts.URL + "/mcp"
			}
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Error(err)
				return
			}
			// The peer (127.0.0.1) is a trusted proxy, so the forwarded
			// address decides whether the origin gate lets the /mcp
			// request through — independent of the loopback peer every
			// request in this test actually arrives from.
			if refused {
				req.Header.Set("X-Forwarded-For", "203.0.113.9")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
		}(i%2 == 0)
	}
	wg.Wait()

	// -race is the actual assertion here; this is a secondary sanity
	// check that nothing got corrupted along the way. A refused request
	// writes two lines (the origin-refusal line and accesslog's own),
	// an allowed one writes one.
	trimmed := strings.TrimRight(buf.String(), "\n")
	var lines []string
	if trimmed != "" {
		lines = strings.Split(trimmed, "\n")
	}
	const wantLines = n/2*2 + n/2
	if len(lines) != wantLines {
		t.Errorf("got %d log lines from %d concurrent requests, want %d", len(lines), n, wantLines)
	}
}
