// Package accesslog writes an access log in NGINX combined format, so
// existing analysers such as CrowdSec work without custom parsers.
package accesslog

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

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
				r.Referer(), r.UserAgent(),
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
