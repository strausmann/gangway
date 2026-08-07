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
