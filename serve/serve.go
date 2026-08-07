package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/strausmann/gangway/access"
	"github.com/strausmann/gangway/accesslog"
	"github.com/strausmann/gangway/identity"
	"github.com/strausmann/gangway/origin"
)

// methodCallTool is the JSON-RPC method name the MCP spec assigns to a
// tool invocation. The SDK keeps its own copy of this string unexported
// (it is only ever compared against, never constructed, by SDK-external
// code), but the name itself is part of the wire protocol, not an SDK
// implementation detail — duplicating it here is safe and lets the
// tool-authorization middleware recognise the one method it needs to
// inspect.
const methodCallTool = "tools/call"

// CodeForbidden is the JSON-RPC error code the tool-authorization
// middleware (installed by AttachMCP) uses to report a refused tool
// call. Per the SDK's own protocol documentation, -32000 to -32019 is
// implementation-defined (the range third-party code should use) while
// -32020 to -32099 is reserved for the MCP specification itself (see
// mcp.CodeHeaderMismatch and neighbours, which live there). Within the
// implementation-defined range, -32001, -32003, -32004 and -32005 are
// already live internally in the SDK's jsonrpc2 layer (unknown error,
// client/server closing, transport rejection) and could in principle
// reach the wire; -32002 was CodeResourceNotFound's value before
// SEP-2164 and can still appear under a documented compatibility flag.
// -32010 avoids all of those.
const CodeForbidden int64 = -32010

// wellKnownProtectedResourcePath is the RFC 9728 discovery path a
// connector fetches after receiving the WWW-Authenticate challenge (see
// challenge). Handler and challenge share this one constant so the
// pointer challenge hands out and the route Handler actually serves can
// never drift apart.
const wellKnownProtectedResourcePath = "/.well-known/oauth-protected-resource"

// syncWriter serializes writes to an underlying io.Writer. New wraps
// whatever WithLogWriter configured (or os.Stdout, by default) in one of
// these — see WithLogWriter for why: at least two independent call sites
// write into the same stream per request in the general case, from
// concurrently handled requests, and most io.Writer implementations
// (a bytes.Buffer, many third-party log rotators) are not themselves safe
// for concurrent use. Without this, concurrent writes can interleave
// mid-line or corrupt the underlying buffer.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// Server is an assembled, ready-to-run MCP server front end.
//
// A Server on its own only ever serves /healthz: without a call to
// AttachMCP, the assembled handler has nothing to route /mcp requests to.
// AttachMCP is the only way to wire an *mcp.Server into a Server, and it
// leaves no way to end up with tool calls that bypass authorization: it
// takes the bare *mcp.Server — before any HTTP handler has been built
// from it — installs the tool-authorization middleware itself, and
// builds the HTTP handler itself with stateless sessions forced on. A
// caller cannot build that handler another way and hand it in instead;
// there is no exported constructor for it that skips either step.
type Server struct {
	cfg       *Config
	verifier  identity.Verifier
	decider   access.Decider
	logs      io.Writer
	toolKinds map[string]access.ToolKind
	list      origin.List
	mcp       http.Handler // built by AttachMCP from the *mcp.Server it receives
}

// Option adjusts the assembly.
type Option func(*Server)

// WithDecider replaces the shipped read/write grid.
func WithDecider(d access.Decider) Option { return func(s *Server) { s.decider = d } }

// WithLogWriter redirects the access log. Defaults to stdout.
//
// The writer itself does not need to be safe for concurrent use: New wraps
// whatever is configured (this option's writer, or the os.Stdout default)
// in an internal serializing writer. At least two independent call sites
// write into it per request in the general case — accesslog.Middleware and
// the origin gate's rejection hook — from concurrently handled requests,
// and a caller providing, say, a plain bytes.Buffer or an unbuffered file
// handle should not have to reason about that to get correct output.
func WithLogWriter(w io.Writer) Option { return func(s *Server) { s.logs = w } }

// WithToolKinds tells the tool-authorization middleware installed by
// AttachMCP how to classify tools by name as reading or writing.
//
// The SDK does not expose a registered tool's annotations to receiving
// middleware — a tools/call request only ever carries the tool's name and
// raw arguments, nothing about how the tool was registered. This mapping
// is therefore the only way the middleware can tell a reading tool from a
// writing one. A tool name absent from the map is treated as writing: a
// forgotten entry must fail closed, not quietly permit everyone to call a
// tool nobody classified.
func WithToolKinds(kinds map[string]access.ToolKind) Option {
	return func(s *Server) { s.toolKinds = kinds }
}

// New verifies the configuration and prepares every layer.
//
// It fails when the issuer cannot be reached or the allowlist cannot be
// built — either because none is configured, or because a configured
// remote source cannot be fetched: a server that can neither authenticate
// nor filter must not come up.
//
// ctx governs the lifetime of the background work New starts: the
// verifier's periodic key refresh and, if a remote allowlist is
// configured, its periodic re-fetch. Pass a context whose lifetime
// matches the server's, not a short-lived request-scoped context, or that
// background work silently stops refreshing once ctx ends.
func New(ctx context.Context, cfg *Config, opts ...Option) (*Server, error) {
	s := &Server{
		cfg:  cfg,
		logs: os.Stdout,
		decider: access.NewGrid(access.GridConfig{
			WritersClaim:        cfg.WritersClaim,
			WritersValue:        cfg.WritersValue,
			AllowWriteByDefault: cfg.AllowWriteByDefault,
		}),
	}
	for _, o := range opts {
		o(s)
	}
	s.logs = &syncWriter{w: s.logs}

	var err error
	s.verifier, err = identity.NewOIDC(ctx, identity.OIDCConfig{
		IssuerURL:    cfg.IssuerURL,
		Audience:     cfg.Audience,
		SubjectClaim: cfg.SubjectClaim,
	})
	if err != nil {
		return nil, err
	}

	if s.list, err = s.buildAllowList(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

// buildAllowList assembles the configured allowlist once, at New time.
// Handler reuses the result on every call instead of rebuilding it:
// rebuilding would mean starting a fresh background refresh goroutine
// (see origin.NewRemoteList) on every call to Handler, leaking one more
// each time.
func (s *Server) buildAllowList(ctx context.Context) (origin.List, error) {
	lists := make([]origin.List, 0, 2)
	if len(s.cfg.AllowedPrefixes) > 0 {
		lists = append(lists, origin.Static(s.cfg.AllowedPrefixes))
	}
	if s.cfg.RemoteListURL != "" {
		remote, err := origin.NewRemoteList(ctx, origin.RemoteListConfig{
			URL:      s.cfg.RemoteListURL,
			Interval: s.cfg.RemoteListInterval,
			Parse:    origin.ParseOpenAIPrefixes,
		})
		if err != nil {
			return nil, err
		}
		lists = append(lists, remote)
	}
	if len(lists) == 0 {
		// LoadConfig already refuses a configuration with neither a
		// static nor a remote allowlist, but New can also be called
		// directly with a hand-built Config — the same rule must hold
		// there too, not just for the environment-driven path.
		return nil, errors.New("gangway: no allowlist configured")
	}
	return origin.Combine(lists...), nil
}

// AttachMCP takes the bare MCP server — not yet wrapped in any HTTP
// handler — and turns it into gw's /mcp endpoint. Call it before Handler
// or Run; Handler reads the handler AttachMCP built, once, when called.
//
// AttachMCP owns two properties that must both hold and that no
// caller-supplied handler could be trusted to have, so it does not offer
// a way to supply one:
//
//  1. Every tool call runs through the authorization middleware. AttachMCP
//     installs it itself (mcpServer.AddReceivingMiddleware(...)) — there is
//     no separate step to forget.
//  2. The server runs stateless (mcp.StreamableHTTPOptions.Stateless =
//     true), hardcoded, not a caller-visible option. In a stateful
//     session (the SDK's own default), the SDK dispatches every JSON-RPC
//     message on that session — including a tools/call arriving on a
//     POST long after the session was opened — through the single
//     context captured once, when the session was created by the
//     initialize request; a later request's own context (and, with it,
//     the outcome tracker accesslog.Middleware attached to that specific
//     HTTP request) never reaches the middleware. Stateless mode opens
//     and closes one temporary session per HTTP request instead, so the
//     context the middleware sees is always the current request's own.
//     IdentityFrom and accesslog.MarkToolOutcome (see toolMiddleware)
//     both depend on that: neither is wrong in stateful mode — the
//     authorization decision itself is unaffected — but IdentityFrom
//     could return a caller that authenticated the session rather than
//     the one who sent this particular call, and the denial or approval
//     the middleware records could attach to an access-log line for a
//     request that already finished, invisible to anyone reading the
//     log.
//
// Both are structural, not documented conventions: there is no exported
// way to reach a *Server's /mcp handler that skips either one.
func (s *Server) AttachMCP(mcpServer *mcp.Server) {
	mcpServer.AddReceivingMiddleware(s.toolMiddleware())
	s.mcp = mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)
}

// toolMiddleware returns the MCP receiving middleware that authorizes
// each tool call. AttachMCP installs it; it is not exported because
// AttachMCP is the only correct place to install it — see AttachMCP for
// why (stateless sessions are what make the context this middleware
// relies on trustworthy).
//
// Order matters at the HTTP layer (see Handler); at the MCP layer there
// is exactly one concern to enforce, so no ordering question arises
// there.
//
// A refusal is reported as an MCP protocol error (CodeForbidden), never
// as an HTTP error: the streamable HTTP transport answers a refused tool
// call with the same HTTP 200 it would use for a successful one, carrying
// the refusal in the JSON-RPC response body instead. That is why every
// outcome — allowed or denied — is also recorded via
// accesslog.MarkToolOutcome: without it, a refusal here would be
// invisible to anything reading the access log for HTTP status codes
// alone.
func (s *Server) toolMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != methodCallTool {
				return next(ctx, method, req)
			}

			// The SDK routes every "tools/call" request through exactly
			// this concrete type (see mcp.CallToolRequest); a value of
			// any other shape here would mean the SDK's own request
			// routing is broken, which is worth failing loudly on rather
			// than silently waving the call through unauthorized.
			call := req.(*mcp.CallToolRequest)
			tool := call.Params.Name

			kind, known := s.toolKinds[tool]
			if !known {
				// A tool this server never classified is treated as
				// writing: a forgotten classification must fail closed
				// and require the writer role, not quietly let everyone
				// call it.
				kind = access.KindWrite
			}

			id, _ := IdentityFrom(ctx)
			if err := s.decider.Allow(ctx, access.Request{Tool: tool, Kind: kind, Identity: id}); err != nil {
				accesslog.MarkToolOutcome(ctx, tool, false)
				return nil, &jsonrpc.Error{Code: CodeForbidden, Message: "forbidden"}
			}
			accesslog.MarkToolOutcome(ctx, tool, true)
			return next(ctx, method, req)
		}
	}
}

// Handler returns the fully wrapped HTTP handler.
//
// Order matters and is the point of this function:
//
//	access log        outermost, so refusals are recorded too
//	  origin gate     before the body is read
//	    authenticate  before the MCP layer sees anything — but only for
//	                  /mcp; /healthz and the RFC 9728 metadata document
//	                  are reachable without a token (the latter
//	                  deliberately: see the route registration below)
//	      MCP handler tool authorization lives inside, in SDK middleware
//	                  installed by AttachMCP (see toolMiddleware)
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Deliberately not behind authenticate: this is the document a
	// connector fetches in response to the WWW-Authenticate challenge
	// (see challenge), before it has a token — gating it would mean the
	// pointer a 401 hands out itself resolves to a 401, a loop with no
	// way out for a connector that only knows to follow the standard
	// discovery flow.
	mux.Handle(wellKnownProtectedResourcePath, auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               strings.TrimSuffix(s.cfg.PublicBaseURL, "/"),
		AuthorizationServers:   []string{s.cfg.IssuerURL},
		BearerMethodsSupported: []string{"header"},
	}))
	if s.mcp != nil {
		mux.Handle("/mcp", s.authenticate(s.mcp))
	}

	gate := origin.Gate(origin.GateConfig{
		Allow:   s.list,
		Trusted: s.cfg.TrustedProxies,
		Mode:    s.cfg.HeaderMode,
		OnReject: func(r *http.Request, addr netip.Addr) {
			// r.URL.Path is decoded, attacker-controlled input: without
			// escaping, a %0A in the request path becomes a real
			// newline here, forging an extra, unescaped line into the
			// same stream accesslog.Middleware writes into — one that
			// could be attributed to any address and status the
			// attacker chooses. EscapeField applies the identical
			// escaping Middleware itself applies, so this stays a
			// single line no matter what the path contains.
			_, _ = fmt.Fprintf(s.logs, "origin refused: addr=%s path=%s\n",
				addr, accesslog.EscapeField(r.URL.Path))
		},
	})

	return accesslog.Middleware(s.logs)(gate(mux))
}

// authenticate verifies the bearer token and places the identity in the
// context.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" || raw == r.Header.Get("Authorization") {
			s.challenge(w)
			return
		}

		id, err := s.verifier.Verify(r.Context(), raw)
		if err != nil {
			s.challenge(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(identityInto(r.Context(), id)))
	})
}

// challenge answers with the pointer a connector needs to start signing
// in. The public base URL is configured, never derived from headers —
// otherwise a caller could redirect the sign-in flow to a server of its
// own choosing.
func (s *Server) challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer resource_metadata="%s%s"`,
		strings.TrimSuffix(s.cfg.PublicBaseURL, "/"), wellKnownProtectedResourcePath))
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

type identityKey struct{}

func identityInto(ctx context.Context, id *identity.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the verified caller placed into the context by the
// HTTP authentication layer (see Server.Handler). Tools use it to learn
// who is calling; the tool-authorization middleware installed by
// AttachMCP uses it to build the authorization request.
func IdentityFrom(ctx context.Context) (*identity.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(*identity.Identity)
	return id, ok
}

// Run serves until ctx is cancelled, then shuts down in an orderly
// fashion.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
