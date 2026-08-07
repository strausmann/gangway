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
// log_format escaping does (`\xXX` for each byte that needs it). Referer
// and User-Agent come straight from the client; without this, a value
// containing a double quote closes the field early and lets the rest of
// the header be read as forged, additional log fields — e.g. a fabricated
// mcp_outcome="allowed" appended by the attacker rather than by this
// package.
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
				r.Method, r.URL.RequestURI(), r.Proto,
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
