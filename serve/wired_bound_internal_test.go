package serve

// This file is package serve, not serve_test, deliberately: proving
// maxWiredInstances holds at the exact boundary means calling the
// unexported ensureWired directly (and, for the seeding step in the
// second test, calling it many times without paying for a real HTTP
// round trip each time) — neither is reachable from the external test
// package the rest of this directory's tests live in. Everything else
// here is self-contained rather than shared with serve_test.go, which is
// a different package and not visible from this one.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/strausmann/gangway/identity"
	"github.com/strausmann/gangway/identity/testidp"
)

// boundLogBuf is a minimal mutex-guarded log sink, mirroring serve_test.go's
// syncBuffer without depending on it (that type lives in package
// serve_test, unreachable from here).
type boundLogBuf struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *boundLogBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *boundLogBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// boundTestBearerTransport injects a bearer token into every outgoing
// request, mirroring serve_test.go's bearerRoundTripper for the same
// reason boundLogBuf mirrors syncBuffer.
type boundTestBearerTransport struct{ token string }

func (t boundTestBearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(r)
}

func freshMCPServerForBoundTest() *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{Name: "bound-test", Version: "0.0.0"}, nil)
}

// TestEnsureWiredEnforcesExactBound is the direct, exhaustive proof for
// maxWiredInstances: exactly that many distinct, never-before-seen
// instances are admitted, the very next one is refused, the refusal is
// reported both to the caller (ok=false, nil) and to the operator (a
// diagnostic log line) — and, the point of the whole exercise, refusal
// only ever applies to instances the bound has not already made room for:
// every instance admitted before the bound tripped keeps working
// afterwards, and the bound stays tripped rather than flapping back once
// a rejected entry's bookkeeping is cleaned up.
func TestEnsureWiredEnforcesExactBound(t *testing.T) {
	var logs boundLogBuf
	s := &Server{logs: &logs}

	admitted := make([]*mcp.Server, 0, maxWiredInstances)
	for i := range maxWiredInstances {
		fresh := freshMCPServerForBoundTest()
		wired, ok := s.ensureWired(fresh)
		if !ok || wired != fresh {
			t.Fatalf("instance %d: ensureWired = (%p, %v), want (%p, true) — the bound must not trip before maxWiredInstances admissions", i, wired, ok, fresh)
		}
		admitted = append(admitted, fresh)
	}

	if logs.String() != "" {
		t.Fatalf("log written to while still under the bound: %q", logs.String())
	}

	overflow := freshMCPServerForBoundTest()
	if wired, ok := s.ensureWired(overflow); ok || wired != nil {
		t.Fatalf("instance %d (one past the bound): ensureWired = (%p, %v), want (nil, false)", maxWiredInstances, wired, ok)
	}
	if !strings.Contains(logs.String(), "mcp instance limit reached") {
		t.Errorf("no diagnostic line written on overflow, log = %q", logs.String())
	}

	// The alarm must specifically stop admitting NEW instances, not
	// un-admit ones it already accepted. Re-checking a handful from the
	// admitted set (not all 1024, to keep this fast) after the overflow
	// proves that.
	for _, idx := range []int{0, maxWiredInstances / 2, maxWiredInstances - 1} {
		if wired, ok := s.ensureWired(admitted[idx]); !ok || wired != admitted[idx] {
			t.Errorf("re-wiring already-admitted instance %d after overflow = (%p, %v), want (%p, true) — the bound must not un-admit an instance it already accepted", idx, wired, ok, admitted[idx])
		}
	}

	// A second, independent overflow attempt must fail exactly the same
	// way as the first — rejecting one instance must not be a one-time
	// event that then lets the next previously-unseen instance through
	// by mistake.
	if wired, ok := s.ensureWired(freshMCPServerForBoundTest()); ok || wired != nil {
		t.Errorf("second overflow attempt = (%p, %v), want (nil, false) — the bound must keep rejecting new instances, not just the first one", wired, ok)
	}
}

// TestEnsureWiredBoundHoldsUnderConcurrentDistinctInstances is the
// concurrent counterpart to TestEnsureWiredEnforcesExactBound: the exact
// version above proves the boundary is correct when instances arrive one
// at a time; this proves it stays exact when many goroutines each present
// their own brand-new, never-before-seen instance at once, right at the
// edge of capacity. Unlike the earlier, already-proven concurrent case
// (many requests racing for the *same* new instance — see
// AttachMCPSelector's own doc comment), this is many requests racing for
// *different* new instances while only a few admission slots remain: the
// case in which a naive "read the count, decide, then increment" would
// let more than maxWiredInstances instances through.
func TestEnsureWiredBoundHoldsUnderConcurrentDistinctInstances(t *testing.T) {
	var logs boundLogBuf
	s := &Server{logs: &logs}

	const remainingSlots = 10
	const racers = 500 // far more than remainingSlots, so contention is certain

	for range maxWiredInstances - remainingSlots {
		if _, ok := s.ensureWired(freshMCPServerForBoundTest()); !ok {
			t.Fatalf("seeding failed unexpectedly")
		}
	}

	var wg sync.WaitGroup
	results := make([]bool, racers)
	wg.Add(racers)
	for i := range racers {
		go func() {
			defer wg.Done()
			_, ok := s.ensureWired(freshMCPServerForBoundTest())
			results[i] = ok
		}()
	}
	wg.Wait()

	accepted := 0
	for _, ok := range results {
		if ok {
			accepted++
		}
	}
	if accepted != remainingSlots {
		t.Errorf("accepted = %d of %d racing distinct instances, want exactly %d (the remaining capacity) — neither more (bound breached) nor fewer (capacity wasted)", accepted, racers, remainingSlots)
	}
	// wiredCount counts admission *attempts*, not admissions — see
	// ensureWired's doc comment on why it is never decremented for a
	// rejection. Every one of the racers, accepted or not, is a distinct
	// instance ensureWired had never seen before, so it advances the
	// counter by exactly one each: the deterministic total is the seeded
	// count plus racers, not maxWiredInstances.
	wantCount := int64(maxWiredInstances-remainingSlots) + racers
	if got := s.wiredCount.Load(); got != wantCount {
		t.Errorf("wiredCount after the race = %d, want exactly %d", got, wantCount)
	}
}

// TestSelectorBeyondBoundFailsVisiblyWhileAdmittedInstancesKeepWorking is
// the end-to-end counterpart to TestEnsureWiredEnforcesExactBound: it
// drives the real Handler, not ensureWired directly, to prove what an
// operator or a caller actually observes once the bound trips — a real
// HTTP failure for the caller routed to the never-before-seen instance
// that pushed the count over the edge, a real successful MCP session for
// a caller routed to an instance admitted before that, and a diagnostic
// line in the log either way.
//
// It seeds every slot but one directly through ensureWired rather than
// with 1024 real HTTP round trips: the exact-boundary bookkeeping is
// already proven exhaustively above, so repeating it here through the
// much slower path would add runtime without adding coverage. The one
// thing this test adds — that AttachMCPSelector's own HTTP-facing
// wiring reacts correctly to ensureWired's answer — only needs the
// boundary crossed once, live.
func TestSelectorBeyondBoundFailsVisiblyWhileAdmittedInstancesKeepWorking(t *testing.T) {
	idp := testidp.New(t)
	var logs boundLogBuf

	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", idp.URL())
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "127.0.0.1/32,::1/128")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	gw, err := New(context.Background(), cfg, WithLogWriter(&logs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	admittedInstance := freshMCPServerForBoundTest()
	if _, ok := gw.ensureWired(admittedInstance); !ok {
		t.Fatalf("seeding the first admitted instance failed unexpectedly")
	}
	for i := 1; i < maxWiredInstances; i++ {
		if _, ok := gw.ensureWired(freshMCPServerForBoundTest()); !ok {
			t.Fatalf("seeding instance %d failed unexpectedly, want all %d to be admitted", i, maxWiredInstances)
		}
	}

	overflowInstance := freshMCPServerForBoundTest()
	gw.AttachMCPSelector(func(_ context.Context, id *identity.Identity) *mcp.Server {
		if id != nil && id.Claims["sub"] == "user-admitted" {
			return admittedInstance
		}
		return overflowInstance
	})

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	admittedToken := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-admitted",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	overflowToken := idp.Token(map[string]any{
		"iss": idp.URL(), "aud": "mcp-server", "sub": "user-overflow",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	// The caller routed to the already-admitted instance gets a real,
	// working MCP session — the bound has nothing to say about an
	// instance it accepted before tripping.
	client := mcp.NewClient(&mcp.Implementation{Name: "bound-test-client", Version: "0.0.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: boundTestBearerTransport{token: admittedToken}},
		DisableStandaloneSSE: true,
	}
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("Connect to the already-admitted instance failed: %v — the bound must not affect an instance admitted before it tripped", err)
	}
	_ = session.Close()

	// The caller routed to the brand-new, never-before-seen instance that
	// would push the count past the bound is refused — a real MCP
	// connection failure, not a silently accepted request. This uses the
	// same well-formed client.Connect path as the admitted case above,
	// deliberately not a hand-built, minimal POST body: an
	// under-specified request (e.g. a bare "{}") gets its own 400 from
	// the SDK's own JSON-RPC parsing regardless of what ensureWired
	// decided, which would make a bare status-code assertion pass or
	// fail for the wrong reason and prove nothing about the bound
	// specifically. Driving the identical, valid handshake for both
	// tokens and only varying which instance the selector routes to
	// isolates the bound as the one difference between the two outcomes.
	overflowClient := mcp.NewClient(&mcp.Implementation{Name: "bound-test-client-overflow", Version: "0.0.0"}, nil)
	overflowTransport := &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: boundTestBearerTransport{token: overflowToken}},
		DisableStandaloneSSE: true,
	}
	if overflowSession, err := overflowClient.Connect(context.Background(), overflowTransport, nil); err == nil {
		_ = overflowSession.Close()
		t.Fatal("Connect to the beyond-bound instance succeeded, want it refused — a caller routed to a rejected instance must see a real failure, not a silently accepted request")
	}

	if !strings.Contains(logs.String(), "mcp instance limit reached") {
		t.Errorf("no diagnostic line reached the operator's log for the beyond-bound request, log = %q", logs.String())
	}
}
