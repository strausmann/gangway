package origin_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/strausmann/gangway/origin"
)

func TestGate(t *testing.T) {
	allow := origin.Static(mustPrefixes(t, "160.79.104.0/21"))
	trusted := mustPrefixes(t, "172.16.0.0/12")

	tests := []struct {
		name       string
		remoteAddr string
		header     string
		wantStatus int
		// wantAddr is checked against the context address when wantStatus
		// is 200. It must be the address that was actually authorised —
		// not merely "some address" — or a bug that swaps in the wrong
		// one (e.g. the immediate peer instead of the header-derived
		// origin) would pass unnoticed.
		wantAddr netip.Addr
	}{
		{
			name:       "allowed provider through trusted proxy",
			remoteAddr: "172.20.0.5:5000",
			header:     "160.79.104.1",
			wantStatus: http.StatusOK,
			wantAddr:   netip.MustParseAddr("160.79.104.1"),
		},
		{
			name:       "unlisted address is refused",
			remoteAddr: "172.20.0.5:5000",
			header:     "203.0.113.9",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "forged header from untrusted peer is refused",
			remoteAddr: "203.0.113.9:5000",
			header:     "160.79.104.1",
			wantStatus: http.StatusForbidden,
		},
		{
			// The peer itself sits inside the allowed range and reaches
			// the server directly, with no trusted proxy in front. The
			// header carries an unrelated, entirely different address —
			// it must be ignored (the peer is not in Trusted), and the
			// context must hold the peer's own address, not the one
			// quoted in the header.
			name:       "direct connection from an allowed peer ignores an untrusted header",
			remoteAddr: "160.79.104.5:6000",
			header:     "203.0.113.9",
			wantStatus: http.StatusOK,
			wantAddr:   netip.MustParseAddr("160.79.104.5"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var reached bool
			h := origin.Gate(origin.GateConfig{
				Allow:   allow,
				Trusted: trusted,
				Mode:    origin.ModeXForwardedFor,
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				addr, ok := origin.AddrFrom(r.Context())
				if !ok {
					t.Error("client address missing from context")
				}
				if addr != tc.wantAddr {
					t.Errorf("context addr = %v, want %v", addr, tc.wantAddr)
				}
				w.WriteHeader(http.StatusOK)
			}))

			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			r.Header.Set("X-Forwarded-For", tc.header)
			w := httptest.NewRecorder()

			h.ServeHTTP(w, r)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusForbidden && reached {
				t.Error("handler ran despite refusal")
			}
		})
	}
}

func TestGateRefusalIsTerse(t *testing.T) {
	h := origin.Gate(origin.GateConfig{
		Allow:   origin.Static(nil),
		Trusted: nil,
		Mode:    origin.ModeXForwardedFor,
	})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "203.0.113.9:5000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// The reason belongs in the log, not in the response: a caller who is
	// turned away should not learn why.
	if body := w.Body.String(); len(body) > 32 {
		t.Errorf("refusal body is %d bytes, want a terse one: %q", len(body), body)
	}
	if strings.Contains(w.Body.String(), "203.0.113.9") {
		t.Error("the refusal echoes the caller's address back to them")
	}
}

func TestGateCallsOnRejectWithTheRefusedAddress(t *testing.T) {
	allow := origin.Static(mustPrefixes(t, "160.79.104.0/21"))

	var gotAddr netip.Addr
	var gotReq *http.Request
	calls := 0

	h := origin.Gate(origin.GateConfig{
		Allow: allow,
		Mode:  origin.ModeXForwardedFor,
		OnReject: func(r *http.Request, addr netip.Addr) {
			calls++
			gotReq = r
			gotAddr = addr
		},
	})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler must not run when the caller is refused")
	}))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "203.0.113.9:5000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if calls != 1 {
		t.Fatalf("OnReject called %d times, want 1", calls)
	}
	want := netip.MustParseAddr("203.0.113.9")
	if gotAddr != want {
		t.Errorf("OnReject addr = %v, want %v", gotAddr, want)
	}
	if gotReq != r {
		t.Error("OnReject did not receive the original request")
	}
}

func TestGatePanicsWithoutAnAllowList(t *testing.T) {
	// A GateConfig with no Allow list is a caller mistake: without it,
	// every request would be refused (Allow.Contains would nil-panic on
	// the first request anyway). Panicking here, when the middleware is
	// built, surfaces the mistake at startup — not on the first request
	// in production.
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Gate did not panic with a nil Allow list")
		}
	}()

	origin.Gate(origin.GateConfig{
		Mode: origin.ModeXForwardedFor,
		// Allow deliberately left nil.
	})
}

func TestGateWithoutOnRejectDoesNotPanic(t *testing.T) {
	h := origin.Gate(origin.GateConfig{
		Allow: origin.Static(nil),
		Mode:  origin.ModeXForwardedFor,
		// OnReject deliberately left nil.
	})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "203.0.113.9:5000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}
