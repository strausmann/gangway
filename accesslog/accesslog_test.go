package accesslog_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strausmann/gangway/accesslog"
)

func TestWritesCombinedFormat(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	r.Header.Set("User-Agent", "claude-connector/1.0")
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	for _, want := range []string{
		`160.79.104.1 - - [`,         // address, then the bracketed time
		`"POST /mcp HTTP/1.1" 200 5`, // request, status, byte count
		`"claude-connector/1.0"`,     // user agent
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log line %q is missing %q", line, want)
		}
	}
}

func TestRecordsRefusedToolCall(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// MCP reports a refused tool call in the body; the status stays 200.
		accesslog.MarkToolOutcome(r.Context(), "delete_item", false)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if !strings.Contains(line, `" 200 `) {
		t.Errorf("expected HTTP status 200 in %q", line)
	}
	// Without this field a refused call is invisible to log analysis,
	// because the HTTP status says success.
	if !strings.Contains(line, `mcp_tool="delete_item" mcp_outcome="denied"`) {
		t.Errorf("log line %q is missing the tool outcome", line)
	}
}

func TestRecordsAllowedToolCall(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accesslog.MarkToolOutcome(r.Context(), "list_items", true)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if !strings.Contains(line, `mcp_tool="list_items" mcp_outcome="allowed"`) {
		t.Errorf("log line %q is missing the allowed tool outcome", line)
	}
}

func TestNoToolOutcomeFieldWhenNotMarked(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if strings.Contains(line, "mcp_tool=") {
		t.Errorf("log line %q should not contain a tool outcome field", line)
	}
}

func TestMarkToolOutcomeWithoutMiddlewareIsNoop(t *testing.T) {
	// A context that never passed through Middleware must not panic and
	// must not observably do anything.
	accesslog.MarkToolOutcome(t.Context(), "whatever", true)
}

func TestDefaultsStatusToOKWhenHandlerOnlyWrites(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Never calls WriteHeader explicitly.
		_, _ = w.Write([]byte("ok"))
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if !strings.Contains(line, `" 200 2`) {
		t.Errorf("expected default status 200 and byte count 2 in %q", line)
	}
}

func TestHandlesMalformedRemoteAddr(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "not-a-valid-host-port"
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if !strings.Contains(line, "not-a-valid-host-port - - [") {
		t.Errorf("expected raw RemoteAddr fallback in %q", line)
	}
}

func TestRecordsUnauthorizedStatusCode(t *testing.T) {
	var buf bytes.Buffer

	// A denied credential check answers with a real HTTP status — this is
	// the case log analysis relies on most: distinguishing a scan of
	// rejected credentials from a burst of legitimate traffic.
	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if !strings.Contains(line, `" 401 `) {
		t.Errorf("expected HTTP status 401 in %q", line)
	}
	if strings.Contains(line, `" 200 `) {
		t.Errorf("log line %q must not also report 200 for a 401 response", line)
	}
}

func TestRecordsForbiddenStatusCodeWithoutBody(t *testing.T) {
	var buf bytes.Buffer

	// WriteHeader without a following Write call: the status must still
	// be the one actually set, not silently reset to the 200 default.
	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if !strings.Contains(line, `" 403 0`) {
		t.Errorf("expected HTTP status 403 and 0 bytes in %q", line)
	}
	if strings.Contains(line, `" 200 `) {
		t.Errorf("log line %q must not also report 200 for a 403 response", line)
	}
}

func TestEscapesDoubleQuoteInUserAgent(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	// A raw quote here would close the quoted user-agent field early and
	// let the rest of the value be read as forged extra log fields —
	// e.g. a fabricated mcp_outcome="allowed".
	r.Header.Set("User-Agent", `evil" mcp_outcome="allowed`)
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if strings.Contains(line, `evil" mcp_outcome="allowed`) {
		t.Errorf("log line %q contains an unescaped double quote from the user agent", line)
	}
	if !strings.Contains(line, `evil\x22 mcp_outcome=\x22allowed`) {
		t.Errorf("log line %q does not contain the NGINX-style escaped quote (\\x22): %q", line, line)
	}
	// The escaped line must still open and close exactly two quoted
	// fields (request line + referer + user-agent = 3 quoted fields,
	// each opened and closed once): an even, expected quote count proves
	// no field boundary was forged.
	if n := strings.Count(line, `"`); n != 6 {
		t.Errorf("expected exactly 6 literal quote characters (3 quoted fields) in %q, got %d", line, n)
	}
}

func TestEscapesBackslashInReferer(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	r.Header.Set("Referer", `https://example.com/a\b`)
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if strings.Contains(line, `a\b`) {
		t.Errorf("log line %q contains an unescaped backslash from the referer", line)
	}
	if !strings.Contains(line, `a\x5Cb`) {
		t.Errorf("log line %q does not contain the NGINX-style escaped backslash (\\x5C): %q", line, line)
	}
}

func TestEscapesControlCharacterInUserAgent(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	// net/http header values cannot carry a raw CR/LF, but any other
	// control byte must still be escaped rather than passed through raw
	// — a raw newline here would forge an additional log line.
	r.Header.Set("User-Agent", "before\x01after")
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if strings.Contains(line, "\x01") {
		t.Errorf("log line %q contains a raw control byte from the user agent", line)
	}
	if !strings.Contains(line, `before\x01after`) {
		t.Errorf("log line %q does not contain the NGINX-style escaped control byte (\\x01): %q", line, line)
	}
}

func TestPassesThroughOrdinaryUserAgentUnescaped(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	r.Header.Set("User-Agent", "claude-connector/1.0 (+https://example.com)")
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if !strings.Contains(line, `"claude-connector/1.0 (+https://example.com)"`) {
		t.Errorf("log line %q should pass an ordinary user agent through unescaped", line)
	}
}

func TestEscapesDoubleQuoteInRequestLine(t *testing.T) {
	var buf bytes.Buffer

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// The Go HTTP server itself re-escapes a raw double quote in the path
	// portion of the request line before it ever reaches Middleware (see
	// url.URL.EscapedPath). The query portion is not re-escaped that way,
	// though — net/url.Parse stores RawQuery verbatim, so this is a real,
	// reachable path for a raw double quote to arrive here, not merely a
	// hypothetical one.
	r := httptest.NewRequest(http.MethodGet, `/mcp?x="y`, nil)
	r.RemoteAddr = "160.79.104.1:5000"
	h.ServeHTTP(httptest.NewRecorder(), r)

	line := buf.String()
	if strings.Contains(line, `?x="y`) {
		t.Errorf("log line %q contains an unescaped double quote from the request line", line)
	}
	if !strings.Contains(line, `?x=\x22y`) {
		t.Errorf("log line %q does not contain the NGINX-style escaped quote (\\x22) for the request line: %q", line, line)
	}
	// Exactly one quoted field for the request line itself (referer and
	// user-agent are both empty in this test but still contribute their
	// own pair of quotes): 3 quoted fields, 6 literal quote characters.
	// An injected raw quote would add two more.
	if n := strings.Count(line, `"`); n != 6 {
		t.Errorf("expected exactly 6 literal quote characters (3 quoted fields) in %q, got %d", line, n)
	}
}

// flushRecorder wraps httptest.ResponseRecorder to observe whether Flush
// was forwarded through the middleware. httptest.ResponseRecorder already
// implements http.Flusher, but we need our own counter to prove the call
// reached the underlying writer.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed int
}

func (f *flushRecorder) Flush() {
	f.flushed++
	f.ResponseRecorder.Flush()
}

func TestFlushIsForwardedToUnderlyingWriter(t *testing.T) {
	var buf bytes.Buffer
	fr := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("chunk"))
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter passed to handler does not implement http.Flusher")
		}
		f.Flush()
	}))

	h.ServeHTTP(fr, httptest.NewRequest(http.MethodGet, "/events", nil))

	if fr.flushed != 1 {
		t.Errorf("expected Flush to be forwarded exactly once, got %d", fr.flushed)
	}
}

// TestEscapeFieldMatchesMiddlewareEscaping proves EscapeField applies the
// identical escaping Middleware applies internally — the whole point of
// exporting it is that a second writer into the same stream (serve.Server's
// origin-gate rejection line) gets exactly the same protection, not a
// hand-rolled approximation of it that could drift.
func TestEscapeFieldMatchesMiddlewareEscaping(t *testing.T) {
	const raw = "before\nafter\"quoted\"back\\slash"

	// What Middleware itself produces for this value, via the User-Agent
	// field.
	var buf bytes.Buffer
	h := accesslog.Middleware(&buf)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.RemoteAddr = "160.79.104.1:5000"
	r.Header.Set("User-Agent", raw)
	h.ServeHTTP(httptest.NewRecorder(), r)

	if !strings.Contains(buf.String(), accesslog.EscapeField(raw)) {
		t.Errorf("EscapeField(%q) = %q, not found verbatim in Middleware's own output %q",
			raw, accesslog.EscapeField(raw), buf.String())
	}
}

func TestEscapeFieldEscapesNewline(t *testing.T) {
	got := accesslog.EscapeField("before\nafter")
	if strings.Contains(got, "\n") {
		t.Errorf("EscapeField(%q) = %q, still contains a raw newline", "before\nafter", got)
	}
	if got != `before\x0Aafter` {
		t.Errorf("EscapeField(%q) = %q, want %q", "before\nafter", got, `before\x0Aafter`)
	}
}

func TestEscapeFieldPassesThroughOrdinaryText(t *testing.T) {
	if got := accesslog.EscapeField("/mcp"); got != "/mcp" {
		t.Errorf("EscapeField(%q) = %q, want it unchanged", "/mcp", got)
	}
}

// --- Middleware rejects a nil writer at construction ---

// nilPtrWriter implements io.Writer on a pointer receiver that
// dereferences the receiver, purely to construct a *typed* nil: a nil
// *nilPtrWriter wrapped in an io.Writer interface value is, at the
// interface level, not equal to the bare nil literal — the interface
// carries a concrete type (*nilPtrWriter), only the pointer itself is
// nil. A plain `out == nil` check does not catch this; see
// TestMiddlewarePanicsOnATypedNilWriterForEveryNilableKind.
type nilPtrWriter struct{ buf bytes.Buffer }

func (w *nilPtrWriter) Write(p []byte) (int, error) {
	return w.buf.Write(p) // panics here if w is nil: w.buf dereferences the receiver
}

// mapWriter, sliceWriter, chanWriter and funcWriter round out the set of
// nilable kinds the shared nilguard check covers. None of these write
// anything real; each exists purely to produce a nil value of its
// specific kind, wrapped in io.Writer, for
// TestMiddlewarePanicsOnATypedNilWriterForEveryNilableKind.
type mapWriter map[string]int

func (mapWriter) Write(p []byte) (int, error) { return len(p), nil }

type sliceWriter []byte

func (sliceWriter) Write(p []byte) (int, error) { return len(p), nil }

type chanWriter chan struct{}

func (chanWriter) Write(p []byte) (int, error) { return len(p), nil }

type funcWriter func([]byte) (int, error)

func (f funcWriter) Write(p []byte) (int, error) { return f(p) } // panics if f is nil -- calling a nil func value

// mustPanic runs fn and reports the recovered panic value, or fails the
// test if fn returned normally.
func mustPanic(t *testing.T, fn func()) (recovered any) {
	t.Helper()
	defer func() {
		recovered = recover()
		if recovered == nil {
			t.Fatal("want a panic, got none")
		}
	}()
	fn()
	return nil
}

// TestMiddlewarePanicsOnATypedNilWriterForEveryNilableKind is the
// table-driven regression guard for Middleware's own nil-writer check,
// structured exactly like serve's
// TestNewRejectsATypedNilLogWriterForEveryNilableKind: a real, usable
// writer (this table's own regression guard) alongside a purpose-built
// nil of every kind the shared nilguard check covers, so that removing
// any one case fails precisely the matching subtest here.
func TestMiddlewarePanicsOnATypedNilWriterForEveryNilableKind(t *testing.T) {
	cases := []struct {
		name      string
		writer    io.Writer
		wantPanic bool
	}{
		{"valid writer", &bytes.Buffer{}, false},
		{"bare nil literal", nil, true},
		{"pointer", (*nilPtrWriter)(nil), true},
		{"map", mapWriter(nil), true},
		{"slice", sliceWriter(nil), true},
		{"chan", chanWriter(nil), true},
		{"func", funcWriter(nil), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantPanic {
				r := mustPanic(t, func() { accesslog.Middleware(tc.writer) })
				msg, ok := r.(string)
				if !ok || !strings.Contains(msg, "Middleware") {
					t.Errorf("recovered panic = %#v, want a string mentioning Middleware", r)
				}
				return
			}
			// Must not panic, and the result must still be a working
			// middleware.
			h := accesslog.Middleware(tc.writer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "10.0.0.1:1234"
			h.ServeHTTP(httptest.NewRecorder(), r)
		})
	}
}

// TestMiddlewarePanicsBeforeAnyResponseIsEverWritten proves the nil-writer
// check runs at construction — inside Middleware(out) itself — not inside
// the request handler it would otherwise return. That placement matters
// because Middleware's normal flow calls next.ServeHTTP (writing the
// response) before it ever writes the log line: a check placed after that
// call, inside the per-request handler, would let a caller's response go
// out to the wire and only then panic while logging it — the caller sees
// a seemingly healthy response, and the service silently stops logging
// for its entire remaining lifetime (out is fixed for good at
// construction). Checking eagerly here means Middleware(nil) never even
// returns something `next` can be chained onto: `next` cannot be invoked
// regardless of where in its own body it would have written a response.
func TestMiddlewarePanicsBeforeAnyResponseIsEverWritten(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("must never be reached"))
	})

	mustPanic(t, func() {
		_ = accesslog.Middleware(nil)(next)
	})

	if called {
		t.Error("next handler ran despite Middleware being given a nil writer — the response could already be on the wire before the panic")
	}
}
