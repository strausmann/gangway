package origin_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/strausmann/gangway/origin"
)

func TestStaticListContains(t *testing.T) {
	l := origin.Static(mustPrefixes(t, "160.79.104.0/21"))

	if !l.Contains(netip.MustParseAddr("160.79.104.1")) {
		t.Error("address inside the prefix was rejected")
	}
	if l.Contains(netip.MustParseAddr("203.0.113.1")) {
		t.Error("address outside the prefix was accepted")
	}
}

func TestRemoteListFetchesOnStart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}`))
	}))
	defer srv.Close()

	l, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
		URL:      srv.URL,
		Interval: time.Hour,
		Parse:    origin.ParseOpenAIPrefixes,
	})
	if err != nil {
		t.Fatalf("NewRemoteList: %v", err)
	}
	if !l.Contains(netip.MustParseAddr("198.51.100.5")) {
		t.Error("address from the fetched list was rejected")
	}
}

func TestRemoteListFailsWhenFirstFetchFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// A server that never learned its allowlist must not start.
	if _, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
		URL:      srv.URL,
		Interval: time.Hour,
		Parse:    origin.ParseOpenAIPrefixes,
	}); err == nil {
		t.Error("want error when the first fetch fails, got none")
	}
}

func TestRemoteListFailsWhenParsedListIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Well-formed JSON, but every entry is skipped by Parse (no usable
		// IPv4 prefix survives) — the resulting list is empty.
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv6Prefix":"2001:db8::/32"},{}]}`))
	}))
	defer srv.Close()

	// An empty parsed list must not silently become "everyone allowed" —
	// it must be treated the same as a fetch failure.
	if _, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
		URL:      srv.URL,
		Interval: time.Hour,
		Parse:    origin.ParseOpenAIPrefixes,
	}); err == nil {
		t.Error("want error when the parsed list is empty, got none")
	}
}

// TestRemoteListKeepsLastGoodStateOnLaterFailure was here as a black-box
// test that inferred a background refresh's completion from the request
// having reached the test server. That signal races the refresh's own
// mutex-protected state update: under load and -race, the assertion could
// run in the window after the server received the second (failing)
// request but before remoteList.refresh had finished deciding not to
// touch the state — a run with the safety property inverted (a failed
// refresh discarding the last good state) was observed to pass roughly 1
// time in 4 despite being wrong. The deterministic replacement, driven by
// a per-refresh completion callback instead of the request count, lives
// in list_internal_test.go as
// TestRemoteListKeepsLastGoodStateOnLaterFailure (white-box: the callback
// is an unexported field).

func TestParseOpenAIPrefixesIgnoresNonIPv4Entries(t *testing.T) {
	got, err := origin.ParseOpenAIPrefixes([]byte(
		`{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"},{"ipv6Prefix":"2001:db8::/32"},{}]}`))
	if err != nil {
		t.Fatalf("ParseOpenAIPrefixes: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d prefixes, want 1", len(got))
	}
}

func TestCombineMatchesAnyList(t *testing.T) {
	l := origin.Combine(
		origin.Static(mustPrefixes(t, "160.79.104.0/21")),
		origin.Static(mustPrefixes(t, "10.0.0.0/8")),
	)

	if !l.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Error("address from the second list was rejected")
	}
	if l.Contains(netip.MustParseAddr("203.0.113.1")) {
		t.Error("address outside every combined list was accepted")
	}
}

func TestParseOpenAIPrefixesRejectsInvalidJSON(t *testing.T) {
	if _, err := origin.ParseOpenAIPrefixes([]byte("not json")); err == nil {
		t.Error("want error for invalid JSON, got none")
	}
}

func TestRemoteListFailsWhenURLIsInvalid(t *testing.T) {
	// A control character makes the URL unparsable, which fails before any
	// request is even sent — the http.NewRequestWithContext error path.
	if _, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
		URL:      "http://\x7f",
		Interval: time.Hour,
		Parse:    origin.ParseOpenAIPrefixes,
	}); err == nil {
		t.Error("want error for an unparsable URL, got none")
	}
}

func TestRemoteListFailsWhenServerIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening at this address anymore

	if _, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
		URL:      url,
		Interval: time.Hour,
		Parse:    origin.ParseOpenAIPrefixes,
	}); err == nil {
		t.Error("want error when the server is unreachable, got none")
	}
}

func TestNewRemoteListDefaultsIntervalWhenNonPositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}`))
	}))
	defer srv.Close()

	// Interval left at zero on purpose: it must default rather than spin
	// the background loop as fast as possible.
	l, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
		URL:   srv.URL,
		Parse: origin.ParseOpenAIPrefixes,
	})
	if err != nil {
		t.Fatalf("NewRemoteList: %v", err)
	}
	if !l.Contains(netip.MustParseAddr("198.51.100.5")) {
		t.Error("address from the fetched list was rejected")
	}
}

func TestRemoteListStopsRefreshingWhenContextIsCancelled(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	_, err := origin.NewRemoteList(ctx, origin.RemoteListConfig{
		URL:      srv.URL,
		Interval: 30 * time.Millisecond,
		Parse:    origin.ParseOpenAIPrefixes,
	})
	if err != nil {
		t.Fatalf("NewRemoteList: %v", err)
	}

	// Wait for the event (a background refresh actually running), not the
	// clock — proves the loop is active before we test that it stops.
	deadline := time.After(3 * time.Second)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("background refresh never ran")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	// Let an already in-flight tick settle before taking the baseline.
	time.Sleep(50 * time.Millisecond)
	after := calls.Load()

	time.Sleep(300 * time.Millisecond)
	if got := calls.Load(); got != after {
		t.Errorf("refresh kept running after context cancellation: %d calls at cancel, %d after waiting", after, got)
	}
}

// closeErrTransport lets a test force every response body's Close to fail,
// without needing the test server itself to misbehave: the read still
// comes from the real transport's response, only Close is intercepted.
type closeErrTransport struct {
	base     http.RoundTripper
	closeErr error
}

func (t *closeErrTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &closeErrBody{ReadCloser: resp.Body, err: t.closeErr}
	return resp, nil
}

type closeErrBody struct {
	io.ReadCloser
	err error
}

func (b *closeErrBody) Close() error {
	_ = b.ReadCloser.Close()
	return b.err
}

// closeErrText marks the simulated close failure so the two tests below
// can tell, from the returned error's text, whether it actually surfaced
// or was swallowed in favour of a more useful cause.
const closeErrText = "simulated close failure"

func clientWithCloseErr() *http.Client {
	return &http.Client{Transport: &closeErrTransport{
		base:     http.DefaultTransport,
		closeErr: errors.New(closeErrText),
	}}
}

func TestRemoteListSurfacesCloseErrorWhenNothingElseFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}`))
	}))
	defer srv.Close()

	// The fetch itself succeeds — status 200, a well-formed, non-empty
	// list — but the response body fails to close. With nothing more
	// useful to report, that close error is the only cause available and
	// must be returned rather than discarded.
	_, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
		URL:      srv.URL,
		Interval: time.Hour,
		Parse:    origin.ParseOpenAIPrefixes,
		Client:   clientWithCloseErr(),
	})
	if err == nil {
		t.Fatal("want an error when the response body fails to close, got none")
	}
	if !strings.Contains(err.Error(), closeErrText) {
		t.Errorf("error = %q, want it to mention the close failure (%q)", err.Error(), closeErrText)
	}
}

func TestRemoteListSwallowsCloseErrorWhenAnotherErrorAlreadyWon(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// The fetch fails for a real reason (non-200 status) AND the response
	// body fails to close. A close error is administrative noise next to
	// an actual fetch failure — it must not hide the more useful cause.
	_, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
		URL:      srv.URL,
		Interval: time.Hour,
		Parse:    origin.ParseOpenAIPrefixes,
		Client:   clientWithCloseErr(),
	})
	if err == nil {
		t.Fatal("want an error when the fetch fails, got none")
	}
	if strings.Contains(err.Error(), closeErrText) {
		t.Errorf("error = %q, the close failure must stay hidden behind the status error", err.Error())
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error = %q, want it to mention the status failure", err.Error())
	}
}

// TestRemoteListErrorNeverLeaksURLPathOrQuery guards the security property
// behind hostOnly/withoutURL: RemoteListConfig.URL is caller-supplied and
// might be a signed URL or carry a credential in its path or query. Every
// place refresh (and NewRemoteList's wrap of its first call) can fail must
// report only the host, never the full URL — across every distinct failure
// mode that reaches for the URL, not just the one status-code path a
// casual read might settle for.
func TestRemoteListErrorNeverLeaksURLPathOrQuery(t *testing.T) {
	const secret = "leaked-super-secret-token-must-never-appear-in-a-log"

	assertNoLeak := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("want an error, got none")
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaked the URL's path/query: %v", err)
		}
	}

	t.Run("non-200 status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		_, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
			URL:      srv.URL + "/" + secret + "?token=" + secret,
			Interval: time.Hour,
			Parse:    origin.ParseOpenAIPrefixes,
		})
		assertNoLeak(t, err)
	})

	t.Run("parsed list is empty", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"prefixes":[{}]}`))
		}))
		defer srv.Close()

		_, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
			URL:      srv.URL + "/" + secret + "?token=" + secret,
			Interval: time.Hour,
			Parse:    origin.ParseOpenAIPrefixes,
		})
		assertNoLeak(t, err)
	})

	t.Run("server unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL + "/" + secret + "?token=" + secret
		srv.Close() // nothing is listening at this address anymore

		_, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
			URL:      url,
			Interval: time.Hour,
			Parse:    origin.ParseOpenAIPrefixes,
		})
		assertNoLeak(t, err)
	})

	t.Run("invalid URL", func(t *testing.T) {
		// A control character makes the URL unparsable — the
		// request-construction error path, before any request is sent.
		_, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
			URL:      "http://exchange.example/" + secret + "\n",
			Interval: time.Hour,
			Parse:    origin.ParseOpenAIPrefixes,
		})
		assertNoLeak(t, err)
	})
}

// --- Combine: what "empty" means for a variadic []List ---
//
// Combine(lists ...List) has two structurally different "empty" cases,
// and they behave differently on purpose — see each test below for which
// is which and why:
//
//  1. No arguments at all (or, equivalently from inside Combine, an
//     explicitly empty/nil []List spread with `...`): NOT a nilguard
//     case, does not panic. A union over zero lists is a valid, if
//     unusual, list that denies every address — see
//     TestCombineWithNoListsDeniesEveryAddress.
//  2. A nil List *value* among the arguments: today, calling Contains on
//     the combined list panics the moment it reaches that nil element
//     (a plain interface-method call on nil), because combined.Contains
//     loops over every list and calls l.Contains(addr) unconditionally.
//     Combine now refuses this eagerly, at construction, instead of
//     leaving it for whichever future Contains call happens to be the
//     first to reach the nil element — see
//     TestCombinePanicsOnANilListForEveryNilableKind and
//     TestCombinePanicsOnANilListAmongValidOnes.

// TestCombineWithNoListsDeniesEveryAddress pins case 1 above: Combine()
// must keep returning a List that simply denies everyone, not start
// panicking or erroring just because it was handed nothing to combine.
// serve.buildAllowList already refuses to call Combine with zero lists at
// all (LoadConfig requires at least a static or a remote allowlist), so
// this behaviour is only ever observable through a direct, hand-built
// call to Combine — but Combine's own contract must still be explicit
// about it, not merely "whatever the loop happens to do".
func TestCombineWithNoListsDeniesEveryAddress(t *testing.T) {
	l := origin.Combine()
	if l == nil {
		t.Fatal("Combine() = nil, want a non-nil List")
	}
	if l.Contains(netip.MustParseAddr("160.79.104.1")) {
		t.Error("Combine() with no lists accepted an address; want it to deny every address")
	}
}

// nilPtrList implements origin.List on a pointer receiver that
// dereferences the receiver, purely to construct a *typed* nil: a nil
// *nilPtrList wrapped in an origin.List interface value is, at the
// interface level, not equal to the bare nil literal — the interface
// carries a concrete type (*nilPtrList), only the pointer itself is nil.
// A plain `l == nil` check inside Combine's loop would not catch this;
// see TestCombinePanicsOnANilListForEveryNilableKind.
type nilPtrList struct{ prefixes []netip.Prefix }

func (l *nilPtrList) Contains(addr netip.Addr) bool {
	for _, p := range l.prefixes { // panics here if l is nil: l.prefixes dereferences the receiver
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// mapList, sliceList, chanList and funcList round out the set of nilable
// kinds the shared nilguard check covers. None of these decide anything
// real; each exists purely to produce a nil value of its specific kind,
// wrapped in origin.List, for
// TestCombinePanicsOnANilListForEveryNilableKind.
type mapList map[string]bool

func (mapList) Contains(netip.Addr) bool { return false }

type sliceList []string

func (sliceList) Contains(netip.Addr) bool { return false }

type chanList chan struct{}

func (chanList) Contains(netip.Addr) bool { return false }

type funcList func(netip.Addr) bool

func (f funcList) Contains(addr netip.Addr) bool { return f(addr) } // panics if f is nil -- calling a nil func value

// mustPanic runs fn (expected to call a construction-time guard such as
// origin.Combine or origin.Gate) and reports the recovered panic value,
// or fails the test if fn returned normally. Shared with gate_test.go —
// both guard the same package's nil-List checks and want the identical
// recover-and-report shape.
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

// TestCombinePanicsOnANilListForEveryNilableKind is the table-driven
// regression guard for case 2 above: a valid list (this table's own
// regression guard — TestCombineMatchesAnyList already exercises the
// happy path end-to-end, but a table mixing pass and fail cases needs its
// own passing row too) alongside a purpose-built nil of every kind the
// shared nilguard check covers, so that removing any one case from that
// check fails precisely the matching subtest here — mirroring
// TestNewRejectsATypedNilVerifierForEveryNilableKind in package serve.
func TestCombinePanicsOnANilListForEveryNilableKind(t *testing.T) {
	cases := []struct {
		name      string
		list      origin.List
		wantPanic bool
	}{
		{"valid list", origin.Static(mustPrefixes(t, "160.79.104.0/21")), false},
		{"bare nil literal", nil, true},
		{"pointer", (*nilPtrList)(nil), true},
		{"map", mapList(nil), true},
		{"slice", sliceList(nil), true},
		{"chan", chanList(nil), true},
		{"func", funcList(nil), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantPanic {
				r := mustPanic(t, func() { origin.Combine(tc.list) })
				msg, ok := r.(string)
				if !ok || !strings.Contains(msg, "Combine") {
					t.Errorf("recovered panic = %#v, want a string mentioning Combine", r)
				}
				return
			}
			l := origin.Combine(tc.list)
			// Must not panic on construction, and the result must still
			// work as a real list.
			l.Contains(netip.MustParseAddr("160.79.104.1"))
		})
	}
}

// TestCombinePanicsOnANilListAmongValidOnes proves the check inspects
// every element, not just lists[0]: a nil buried between two otherwise
// valid lists is exactly the shape a caller assembling a []List
// programmatically (appending one entry per configured source, say) could
// produce by accident if one source's list ended up unset.
func TestCombinePanicsOnANilListAmongValidOnes(t *testing.T) {
	valid1 := origin.Static(mustPrefixes(t, "160.79.104.0/21"))
	valid2 := origin.Static(mustPrefixes(t, "10.0.0.0/8"))

	r := mustPanic(t, func() { origin.Combine(valid1, nil, valid2) })
	msg, ok := r.(string)
	if !ok || !strings.Contains(msg, "Combine") {
		t.Errorf("recovered panic = %#v, want a string mentioning Combine", r)
	}
}
