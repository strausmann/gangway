package origin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// TestRemoteListKeepsLastGoodStateOnLaterFailure is a white-box test: it
// needs access to the unexported afterRefresh hook to wait
// deterministically for a specific background refresh to have finished —
// including its state update, if any — rather than inferring completion
// from the request having reached the server. That signal (used in an
// earlier, black-box version of this test in list_test.go) races the
// mutex-protected state update inside refresh: it can fire in the window
// after the server received the request but before refresh has decided
// whether to touch the state, which let a run with the safety property
// inverted (a failed refresh discarding the last good state) pass in
// roughly a quarter of repetitions. This version cannot pass that way: it
// waits on the callback, which refresh invokes only after any state
// change from that exact call has already been applied.
func TestRemoteListKeepsLastGoodStateOnLaterFailure(t *testing.T) {
	var failing atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}`))
	}))
	defer srv.Close()

	cfg := RemoteListConfig{
		URL:      srv.URL,
		Interval: 20 * time.Millisecond,
		Parse:    ParseOpenAIPrefixes,
	}
	// Replicate NewRemoteList's own setup (defaults, initial synchronous
	// fetch, then the background loop) instead of calling it directly, so
	// the completion hook can be installed before the loop's goroutine
	// starts. Installing it afterwards would itself be a data race: the
	// loop goroutine could already be reading the field.
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}

	l := &remoteList{cfg: cfg}
	if err := l.refresh(context.Background()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	if !l.Contains(netip.MustParseAddr("198.51.100.5")) {
		t.Fatal("initial fetch did not populate the list")
	}

	// Every subsequent request the server receives fails, so every
	// background refresh from here on must find the last good state kept.
	failing.Store(true)

	done := make(chan error, 1)
	l.afterRefresh = func(err error) {
		select {
		case done <- err:
		default:
			// A previous signal is still unread; drop this one. The test
			// only needs to observe one completed refresh.
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.loop(ctx)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("want the background refresh to fail once the server starts failing, got success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no background refresh completed in time")
	}

	if !l.Contains(netip.MustParseAddr("198.51.100.5")) {
		t.Error("a failed refresh discarded the last good state — it must be kept")
	}
}
