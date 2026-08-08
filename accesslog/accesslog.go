// Package accesslog writes an access log in NGINX combined format, so
// existing analysers such as CrowdSec work without custom parsers.
package accesslog

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/strausmann/gangway/internal/nilguard"
)

const hexDigits = "0123456789ABCDEF"

// mustEscape reports whether b needs escaping to safely appear inside a
// double-quoted field of the log line: NGINX's default log_format escapes
// the same set — the quote and backslash themselves, plus control bytes
// and anything outside printable ASCII.
func mustEscape(b byte) bool {
	return b == '"' || b == '\\' || b < 0x20 || b > 0x7e
}

// escapeField escapes a request-controlled value the way NGINX's default
// log_format escaping does (`\xXX` for each byte that needs it). Applied
// to every field built from client input — method, request line, proto,
// referer, and user-agent — because without it, a value containing a
// double quote closes the field early and lets the rest be read as
// forged, additional log fields — e.g. a fabricated mcp_outcome="allowed"
// appended by the attacker rather than by this package.
//
// The request line's query string is the field most worth escaping: Go's
// net/http re-escapes a raw double quote in the path portion before
// Middleware ever sees it (see url.URL.EscapedPath), but the query
// portion is stored and reproduced verbatim, so a request like
// "/mcp?x=\"y" reaches here with the quote intact. The method and proto
// fields, by contrast, cannot carry one through a real net/http server —
// ReadRequest rejects a method containing '"' outright, and proto is
// parsed against a strict "HTTP/x.y" pattern — so escaping them is
// defense in depth against a caller that builds *http.Request by hand
// (a custom front end, or a test) rather than a gap seen through the
// standard server.
func escapeField(s string) string {
	escapeCount := 0
	for i := 0; i < len(s); i++ {
		if mustEscape(s[i]) {
			escapeCount++
		}
	}
	if escapeCount == 0 {
		return s
	}

	var b strings.Builder
	b.Grow(len(s) + escapeCount*3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if mustEscape(c) {
			b.WriteByte('\\')
			b.WriteByte('x')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// EscapeField applies the same escaping Middleware applies to every
// request-controlled field it logs (see escapeField). It exists for code
// outside this package that writes into the same log stream Middleware
// writes into but from a different call site — currently serve.Server's
// origin-gate rejection line, which is written directly by an
// origin.GateConfig.OnReject hook, not by Middleware itself.
//
// Anything sharing this package's output stream and skipping this call on
// a request-controlled value reopens exactly the log-forging class of bug
// this package's own escaping closes: an unescaped newline in the value
// lets an attacker inject a fabricated log line — attributed to whatever
// address and fields the attacker chooses — into a stream that feeds
// intrusion detection.
func EscapeField(s string) string { return escapeField(s) }

type outcome struct {
	mu      sync.Mutex
	tool    string
	allowed bool
	set     bool
}

type ctxKey struct{}

// MarkToolOutcome records the result of a tool call for the current
// request.
//
// This exists because MCP reports a refused tool call in the response
// body while the HTTP status stays 200. Without this field, log analysis
// would see nothing but success — the one path that matters most to an
// operator, a call blocked by the address allowlist, would be invisible.
//
// Calling it with a context that never passed through Middleware is a
// no-op, so instrumented handlers do not need to guard the call.
func MarkToolOutcome(ctx context.Context, tool string, allowed bool) {
	o, ok := ctx.Value(ctxKey{}).(*outcome)
	if !ok {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tool, o.allowed, o.set = tool, allowed, true
}

type recorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Flush forwards to the wrapped writer so that MCP's long-lived,
// event-streaming connections are not held back by this middleware. MCP
// keeps connections open and pushes events as they occur; without this
// forwarding the underlying transport buffers the stream, the server
// looks healthy, and nothing reaches the caller until the connection
// closes.
func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware logs every request in NGINX combined format, with two extra
// fields appended for the MCP tool outcome. Existing log analysers that
// only understand the combined format keep working unmodified, because
// the extra fields are appended after the standard ones rather than
// interleaved.
//
// Middleware panics if out is nil — in every sense nilguard.IsNilValue
// checks, not just the bare nil literal — rather than returning a
// middleware that would panic later, on the first request's log line.
// That distinction matters more here than it would for an ordinary
// nil-argument check: the per-request handler below calls
// next.ServeHTTP, which writes the response, *before* it writes to out.
// A nil out caught only there would let the response reach the caller —
// the service looks healthy from the outside — and then panic while
// logging it, permanently: out is fixed for the lifetime of the value
// Middleware returns, so every subsequent request would fail to log the
// exact same way, silently, for as long as the service keeps running.
// Checking here, before Middleware returns anything `next` could ever be
// chained onto, rules that out structurally: next is never invoked, so no
// response can have gone out, however Middleware's caller wires the
// result together (this is why the check sits here and not as the first
// thing inside the returned http.HandlerFunc — that placement would still
// run once per request instead of once, and — for a next that panics or
// hijacks the connection before returning — could in principle still let
// something happen before the check fires).
//
// This differs from origin.Gate's cfg.Allow == nil check by using
// nilguard.IsNilValue instead of a bare comparison: Gate's own doc
// comment already explains why it panics rather than fails a later
// request, and the same reasoning applies here, extended to catch a
// typed nil (a *bytes.Buffer variable that was declared but never
// assigned, say) the bare comparison alone would miss — see
// nilguard.IsNilValue's doc comment for the full mechanics.
func Middleware(out io.Writer) func(http.Handler) http.Handler {
	if nilguard.IsNilValue(out) {
		panic("gangway: accesslog.Middleware(nil) is not a valid writer " +
			"— pass a real io.Writer (os.Stdout, a file, a bytes.Buffer, ...)")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			o := &outcome{}
			rec := &recorder{ResponseWriter: w}

			ctx := context.WithValue(r.Context(), ctxKey{}, o)
			next.ServeHTTP(rec, r.WithContext(ctx))

			if rec.status == 0 {
				rec.status = http.StatusOK
			}

			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}

			line := fmt.Sprintf(`%s - - [%s] "%s %s %s" %d %d "%s" "%s"`,
				host,
				start.Format("02/Jan/2006:15:04:05 -0700"),
				escapeField(r.Method), escapeField(r.URL.RequestURI()), escapeField(r.Proto),
				rec.status, rec.bytes,
				escapeField(r.Referer()), escapeField(r.UserAgent()),
			)

			o.mu.Lock()
			if o.set {
				result := "allowed"
				if !o.allowed {
					result = "denied"
				}
				line += fmt.Sprintf(` mcp_tool=%q mcp_outcome=%q`, o.tool, result)
			}
			o.mu.Unlock()

			// The error from this write is deliberately discarded, and
			// deliberately not escalated into a panic either — this is a
			// design decision, not an oversight, and the two nil checks
			// above this function only cover one half of the problem
			// they were added to close.
			//
			// A nil (or typed-nil) out is caught at construction, before
			// any request is ever served, and failing loudly there is
			// unambiguously correct — no request has been accepted yet,
			// there is nothing to lose by refusing to start. A perfectly
			// valid out that starts failing later — a full disk, a
			// rotated-and-removed file, a closed pipe on the other end —
			// is a different problem, discovered only here, per request,
			// with a response the caller may already be receiving
			// concurrently on the same connection this line is about
			// (Handler's response and this write race by design; see the
			// package doc and recorder above). Two responses to that
			// failure are both wrong for the same reason Middleware
			// itself does not silently swallow a nil writer: turning it
			// into a panic here would fail the request itself over a
			// pure logging problem, punishing the caller for an
			// operational issue with the log sink that has nothing to do
			// with them; but the current out=os.Stdout production default
			// makes a persistent failure here just as invisible as a nil
			// writer would have been before construction ever caught it
			// — the operator loses every log line for as long as out
			// keeps failing, silently, at precisely the moment (a burst
			// of denied tool calls, a CrowdSec-relevant spike) they would
			// most need to see it.
			//
			// Recommendation for closing that gap, deliberately not
			// implemented here: not a panic (couples the request path to
			// the log sink's health) and not an unconditional per-request
			// stderr fallback either (as silent as this, in a
			// containerized deployment where nothing reads stderr, and it
			// would double the write-failure cost on every single
			// request during an outage). Instead, a bounded, out-of-band
			// signal — a counter this package could expose for the
			// caller's own metrics, or an optional callback in a future
			// MiddlewareConfig, invoked with the error but never blocking
			// or influencing the response — so an operator's existing
			// monitoring can page on "log writes have been failing for N
			// requests" without every request paying for it and without
			// this middleware deciding, on the caller's behalf, how loud
			// that alarm should be.
			_, _ = fmt.Fprintln(out, line)
		})
	}
}
