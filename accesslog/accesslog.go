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
func Middleware(out io.Writer) func(http.Handler) http.Handler {
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

			_, _ = fmt.Fprintln(out, line)
		})
	}
}
