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
	}{
		{
			name:       "allowed provider through trusted proxy",
			remoteAddr: "172.20.0.5:5000",
			header:     "160.79.104.1",
			wantStatus: http.StatusOK,
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
				if _, ok := origin.AddrFrom(r.Context()); !ok {
					t.Error("client address missing from context")
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
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))

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
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestGateWithoutOnRejectDoesNotPanic(t *testing.T) {
	h := origin.Gate(origin.GateConfig{
		Allow: origin.Static(nil),
		Mode:  origin.ModeXForwardedFor,
		// OnReject deliberately left nil.
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "203.0.113.9:5000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}
