package accesslog_test

import (
	"bytes"
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
