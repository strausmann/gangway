package origin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

func TestRemoteListKeepsLastGoodStateOnLaterFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// A generous interval: short enough that the test does not stall, but
	// long enough that the background loop does not race the assertions
	// below under -race and load (a 20ms interval was observed to make an
	// earlier test in this codebase flaky for exactly that reason).
	l, err := origin.NewRemoteList(context.Background(), origin.RemoteListConfig{
		URL:      srv.URL,
		Interval: 100 * time.Millisecond,
		Parse:    origin.ParseOpenAIPrefixes,
	})
	if err != nil {
		t.Fatalf("NewRemoteList: %v", err)
	}

	// Wait for the event (a second call reaching the server), not the
	// clock: poll the counter with a generous deadline instead of sleeping
	// a fixed duration and hoping the refresh already ran.
	deadline := time.After(5 * time.Second)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("refresh never ran")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	if !l.Contains(netip.MustParseAddr("198.51.100.5")) {
		t.Error("a failed refresh discarded the last good state — it must be kept")
	}
}

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
