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
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/strausmann/gangway/access"
	"github.com/strausmann/gangway/accesslog"
	"github.com/strausmann/gangway/identity"
	"github.com/strausmann/gangway/origin"
)

// methodCallTool is the JSON-RPC method name the MCP spec assigns to a
// tool invocation. The SDK keeps its own copy of this string unexported
// (it is only ever compared against, never constructed, by SDK-external
// code), but the name itself is part of the wire protocol, not an SDK
// implementation detail — duplicating it here is safe and lets
// Server.ToolMiddleware recognise the one method it needs to inspect.
const methodCallTool = "tools/call"

// CodeForbidden is the JSON-RPC error code Server.ToolMiddleware uses to
// report a refused tool call. JSON-RPC 2.0 reserves -32000 to -32099 for
// implementation-defined server errors; the SDK's own codes in that range
// (see mcp.CodeHeaderMismatch and neighbours) stop at -32042, so -32001
// does not collide with anything the SDK assigns itself.
const CodeForbidden int64 = -32001

// Server is an assembled, ready-to-run MCP server front end.
//
// A Server on its own only ever serves /healthz: without a call to
// AttachMCP, the assembled handler has nothing to route /mcp requests to.
type Server struct {
	cfg       *Config
	verifier  identity.Verifier
	decider   access.Decider
	logs      io.Writer
	toolKinds map[string]access.ToolKind
	list      origin.List
	mcp       http.Handler // set by AttachMCP
}

// Option adjusts the assembly.
type Option func(*Server)

// WithDecider replaces the shipped read/write grid.
func WithDecider(d access.Decider) Option { return func(s *Server) { s.decider = d } }

// WithLogWriter redirects the access log. Defaults to stdout.
func WithLogWriter(w io.Writer) Option { return func(s *Server) { s.logs = w } }

// WithToolKinds tells Server.ToolMiddleware how to classify tools by name
// as reading or writing.
//
// The SDK does not expose a registered tool's annotations to receiving
// middleware — a tools/call request only ever carries the tool's name and
// raw arguments, nothing about how the tool was registered. This mapping
// is therefore the only way ToolMiddleware can tell a reading tool from a
// writing one. A tool name absent from the map is treated as writing (see
// ToolMiddleware): a forgotten entry must fail closed, not quietly permit
// everyone to call a tool nobody classified.
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

// AttachMCP installs the HTTP handler produced by the MCP SDK — typically
// the result of mcp.NewStreamableHTTPHandler wrapping a *mcp.Server that
// has Server.ToolMiddleware installed via AddReceivingMiddleware. Call it
// before Handler or Run; Handler reads the attached handler once, when
// called.
//
// See ToolMiddleware for a requirement on how that handler is built:
// StreamableHTTPOptions.Stateless must be true.
func (s *Server) AttachMCP(h http.Handler) { s.mcp = h }

// ToolMiddleware returns the MCP receiving middleware that authorizes
// each tool call. Install it on the *mcp.Server passed to AttachMCP's
// handler, before wrapping that server in mcp.NewStreamableHTTPHandler
// with StreamableHTTPOptions.Stateless set to true:
//
//	mcpServer.AddReceivingMiddleware(gw.ToolMiddleware())
//	handler := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{Stateless: true})
//	gw.AttachMCP(handler)
//
// Stateless is not optional. In a stateful session (the SDK's own
// default), the SDK dispatches every JSON-RPC message on that session —
// including a tools/call arriving on a POST long after the session was
// opened — through the single context captured once, when the session
// was created by the initialize request; a later request's own context
// (and, with it, the outcome tracker accesslog.Middleware attached to
// that specific HTTP request) never reaches this middleware. In stateless
// mode the SDK opens and closes one temporary session per HTTP request
// (see StreamableHTTPOptions.Stateless), so the context this middleware
// receives is always the current request's own. IdentityFrom and
// accesslog.MarkToolOutcome below both depend on that: neither is wrong
// in stateful mode — the authorization decision itself is unaffected —
// but IdentityFrom can return a caller that authenticated the session
// rather than the one who sent this particular call, and the denial or
// approval this middleware records may attach to an access-log line for
// a request that already finished, making it invisible to anyone
// reading the log.
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
func (s *Server) ToolMiddleware() mcp.Middleware {
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
//	    authenticate  before the MCP layer sees anything
//	      MCP handler tool authorization lives inside, in SDK middleware
//	                  (see ToolMiddleware)
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if s.mcp != nil {
		mux.Handle("/mcp", s.authenticate(s.mcp))
	}

	gate := origin.Gate(origin.GateConfig{
		Allow:   s.list,
		Trusted: s.cfg.TrustedProxies,
		Mode:    s.cfg.HeaderMode,
		OnReject: func(r *http.Request, addr netip.Addr) {
			_, _ = fmt.Fprintf(s.logs, "origin refused: addr=%s path=%s\n", addr, r.URL.Path)
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
		`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`,
		strings.TrimSuffix(s.cfg.PublicBaseURL, "/")))
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

type identityKey struct{}

func identityInto(ctx context.Context, id *identity.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the verified caller placed into the context by the
// HTTP authentication layer (see Server.Handler). Tools use it to learn
// who is calling; Server.ToolMiddleware uses it to build the
// authorization request.
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
