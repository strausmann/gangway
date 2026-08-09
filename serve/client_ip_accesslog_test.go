package serve_test

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strausmann/gangway/identity/testidp"
)

// This file is the regression test for the access log carrying a reverse
// proxy's own address instead of the caller's real one: the combined-format
// line accesslog.Middleware writes used to come from r.RemoteAddr, read
// directly on the *http.Request Middleware itself was handed — but
// Middleware wraps everything else in Server.Handler, including
// origin.Gate, so whatever address Gate resolves from a trusted forwarding
// header only ever lives on Gate's own copy of the request (http.Request.
// WithContext returns a new value) and never reaches Middleware's. Every
// test below exercises the full chain (serve.newServer's h.ServeHTTP), not
// origin or accesslog in isolation, because that ordering problem only
// exists once the layers are actually composed the way Server.Handler
// composes them.
//
// All six use the same allow/trust configuration newServer's helper
// already sets up (GANGWAY_ALLOWED_PREFIXES=160.79.104.0/21,
// GANGWAY_TRUSTED_PROXIES=172.16.0.0/12), the same one origin/gate_test.go
// uses for the equivalent origin-package-level cases.

// logLines splits the buffered log into its individual lines. A rejected
// request can produce two (the origin gate's own OnReject hook, see
// TestOriginRefusalLogLineEscapesForgedNewline elsewhere in this package,
// plus accesslog.Middleware's own combined-format line); the latter is
// always the last one written for a given request, which is what
// TestAccessLogRecordsRealAddressForRejectedRequest below needs to pin
// down precisely rather than asserting on the buffer as a whole.
func logLines(logs *syncBuffer) []string {
	trimmed := strings.TrimRight(logs.String(), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// TestAccessLogRecordsPeerAddressForDirectConnection is requirement 1: a
// caller with no proxy in front of it — the Ollama-on-localhost case named
// in the brief — must see its own address in the log, the same address it
// always saw before origin.Gate or any forwarding header entered the
// picture at all.
func TestAccessLogRecordsPeerAddressForDirectConnection(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	// 160.79.104.5 is inside the allowed range but outside the trusted
	// range: the gate must decide purely from the peer, and the log must
	// show that same peer, not a header — there is deliberately no
	// X-Forwarded-For set at all here, exactly as a direct caller would
	// never send one.
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
	r.RemoteAddr = "160.79.104.5:6000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !strings.Contains(logs.String(), "160.79.104.5 - - [") {
		t.Errorf("access log %q does not record the direct peer's address", logs.String())
	}
}

// TestAccessLogRecordsForwardedAddressThroughTrustedProxy is requirement
// 2: behind a trusted proxy, the log must show the real caller the proxy
// forwarded — the entire point of this fix — not the proxy's own address.
func TestAccessLogRecordsForwardedAddressThroughTrustedProxy(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	request(t, h, "172.20.0.5:5000", "160.79.104.1", token)

	if !strings.Contains(logs.String(), "160.79.104.1 - - [") {
		t.Errorf("access log %q does not record the forwarded address", logs.String())
	}
	if strings.Contains(logs.String(), "172.20.0.5") {
		t.Errorf("access log %q leaks the proxy's own address", logs.String())
	}
}

// TestAccessLogIgnoresForgedForwardedHeaderFromUntrustedPeer is
// requirement 3, the security-critical case: a caller that is not itself
// a trusted proxy can claim to be anyone via X-Forwarded-For. If the log
// believed that claim, the same forged address would reach whatever reads
// this log next — CrowdSec, in this project's own stated use — and an
// attacker could get an innocent third party's address banned instead of
// their own.
func TestAccessLogIgnoresForgedForwardedHeaderFromUntrustedPeer(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	// 203.0.113.9 is the actual caller — outside both the trusted and the
	// allowed ranges — claiming, via the header, to be 160.79.104.1, an
	// address that IS in the allowed range. A caller trusting the header
	// here would both let the request through and log the wrong address.
	w := request(t, h, "203.0.113.9:5000", "160.79.104.1", "")

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403 (the forged header must not grant access)", w.Code)
	}
	if !strings.Contains(logs.String(), "203.0.113.9") {
		t.Errorf("access log %q does not record the real, untrusted peer", logs.String())
	}
	if strings.Contains(logs.String(), "160.79.104.1") {
		t.Errorf("access log %q was fooled by the forged X-Forwarded-For claim", logs.String())
	}
}

// TestAccessLogRecordsRealAddressForRejectedRequest is requirement 4,
// using a request that is refused for an ordinary reason (the resolved
// origin is simply not on the allowlist) rather than an attempted forgery
// — a trusted proxy correctly reporting a caller that just isn't allowed.
// The address an operator needs in order to act on a refusal must reach
// the log exactly the same way as it would for an allowed request.
func TestAccessLogRecordsRealAddressForRejectedRequest(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	w := request(t, h, "172.20.0.5:5000", "203.0.113.9", "")

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	lines := logLines(&logs)
	if len(lines) == 0 {
		t.Fatal("no access log line was written")
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, "203.0.113.9 - - [") {
		t.Errorf("access log line %q does not carry the real address of the refused caller", last)
	}
}

// TestAccessLogRecordsRealAddressForHealthz is requirement 5: /healthz is
// deliberately exempt from origin.Gate (see Server.Handler's own
// comment), but that exemption is about who may probe it, not about
// whether the log line for it may lie about who did.
func TestAccessLogRecordsRealAddressForHealthz(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	r := httptest.NewRequest("GET", "/healthz", nil)
	r.RemoteAddr = "172.20.0.5:5000"
	r.Header.Set("X-Forwarded-For", "160.79.104.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(logs.String(), "160.79.104.1 - - [") {
		t.Errorf("access log %q does not resolve the forwarded address for /healthz", logs.String())
	}
	if strings.Contains(logs.String(), "172.20.0.5") {
		t.Errorf("access log %q leaks the proxy's own address for /healthz", logs.String())
	}
}

// TestAccessLogRecordsRightmostUntrustedAddressInAChain is requirement 6:
// a chain with more than one hop, where the rightmost entries are
// themselves trusted proxies (they appended their own address on the way
// in) and the true origin sits further left, past all of them.
func TestAccessLogRecordsRightmostUntrustedAddressInAChain(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	h := newServer(t, idp, &logs)

	token := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	// 172.20.0.7 and 172.16.5.5 are both inside the trusted range (two
	// hops of proxy); 160.79.104.9 — the true origin — is not, and is
	// also inside the allowed range, so this request is expected to
	// succeed once resolved correctly.
	request(t, h, "172.20.0.5:5000", "160.79.104.9, 172.16.5.5, 172.20.0.7", token)

	if !strings.Contains(logs.String(), "160.79.104.9 - - [") {
		t.Errorf("access log %q does not record the origin past the trusted hops", logs.String())
	}
	for _, hop := range []string{"172.16.5.5", "172.20.0.7"} {
		if strings.Contains(logs.String(), hop) {
			t.Errorf("access log %q leaks an intermediate trusted hop %q", logs.String(), hop)
		}
	}
}
