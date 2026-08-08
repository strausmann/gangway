package backend_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strausmann/gangway/backend"
	"github.com/strausmann/gangway/identity"
)

var caller = &identity.Identity{Subject: "user-123"}

func TestStaticToken(t *testing.T) {
	got, err := backend.StaticToken("service-token").TokenFor(context.Background(), caller, "incoming")
	if err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	if got != "service-token" {
		t.Errorf("token = %q, want %q", got, "service-token")
	}
}

func TestPerUserUsesLookup(t *testing.T) {
	src := backend.PerUser(func(_ context.Context, id *identity.Identity) (string, error) {
		return "token-for-" + id.Subject, nil
	})

	got, err := src.TokenFor(context.Background(), caller, "")
	if err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	if got != "token-for-user-123" {
		t.Errorf("token = %q, want %q", got, "token-for-user-123")
	}
}

func TestPerUserPropagatesLookupError(t *testing.T) {
	src := backend.PerUser(func(context.Context, *identity.Identity) (string, error) {
		return "", fmt.Errorf("no account linked")
	})

	if _, err := src.TokenFor(context.Background(), caller, ""); err == nil {
		t.Error("want error from the lookup, got none")
	}
}

func TestPassThrough(t *testing.T) {
	got, err := backend.PassThrough().TokenFor(context.Background(), caller, "incoming-token")
	if err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	if got != "incoming-token" {
		t.Errorf("token = %q, want %q", got, "incoming-token")
	}
}

func TestExchangeCallsProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if got := r.PostForm.Get("subject_token"); got != "incoming-token" {
			t.Errorf("subject_token = %q, want %q", got, "incoming-token")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"exchanged-token"}`))
	}))
	defer srv.Close()

	src := backend.Exchange(backend.ExchangeConfig{
		TokenURL: srv.URL, ClientID: "gangway", ClientSecret: "secret",
	})

	got, err := src.TokenFor(context.Background(), caller, "incoming-token")
	if err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	if got != "exchanged-token" {
		t.Errorf("token = %q, want %q", got, "exchanged-token")
	}
}

func TestExchangeReportsProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	src := backend.Exchange(backend.ExchangeConfig{TokenURL: srv.URL, ClientID: "gangway"})

	if _, err := src.TokenFor(context.Background(), caller, "incoming"); err == nil {
		t.Error("want error on a rejected exchange, got none")
	}
}

// TestExchangeErrorNeverLeaksResponseBody guards the security property of
// this task: the token-provider's response body can echo back the
// requested (or a freshly issued) token, and that body must never end up
// in an error message — error messages are the kind of text that lands in
// logs. Only the status code may leak.
func TestExchangeErrorNeverLeaksResponseBody(t *testing.T) {
	const secret = "leaked-super-secret-token-must-never-appear-in-a-log"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"access_token":"` + secret + `","error":"invalid_grant"}`))
	}))
	defer srv.Close()

	src := backend.Exchange(backend.ExchangeConfig{TokenURL: srv.URL, ClientID: "gangway"})

	_, err := src.TokenFor(context.Background(), caller, "incoming")
	if err == nil {
		t.Fatal("want error on a rejected exchange, got none")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error message leaked the token-bearing response body: %v", err)
	}
}

// TestExchangeErrorNeverLeaksTokenURL guards the same class of leak as
// TestExchangeErrorNeverLeaksResponseBody, but for ExchangeConfig.TokenURL
// itself: it is caller-supplied and might be a signed URL or carry a
// credential in its path or query. Both http.NewRequestWithContext and
// http.Client.Do wrap their errors in *url.Error, whose own Error() text
// echoes the full URL back verbatim — so both failure paths need covering,
// not just one.
func TestExchangeErrorNeverLeaksTokenURL(t *testing.T) {
	const secret = "leaked-super-secret-token-must-never-appear-in-a-log"

	assertNoLeak := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("want an error, got none")
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaked the token URL's path/query: %v", err)
		}
	}

	t.Run("invalid URL", func(t *testing.T) {
		// A control character makes the URL unparsable — the
		// request-construction error path, before any request is sent.
		src := backend.Exchange(backend.ExchangeConfig{
			TokenURL: "http://exchange.example/" + secret + "\n", ClientID: "gangway",
		})
		_, err := src.TokenFor(context.Background(), caller, "incoming")
		assertNoLeak(t, err)
	})

	t.Run("server unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		tokenURL := srv.URL + "/" + secret + "?token=" + secret
		srv.Close() // nothing is listening at this address anymore

		src := backend.Exchange(backend.ExchangeConfig{TokenURL: tokenURL, ClientID: "gangway"})
		_, err := src.TokenFor(context.Background(), caller, "incoming")
		assertNoLeak(t, err)
	})
}

func TestExchangeNetworkError(t *testing.T) {
	// A server that is closed before the request is made guarantees a
	// transport-level failure (connection refused) rather than an HTTP
	// error response.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tokenURL := srv.URL
	srv.Close()

	src := backend.Exchange(backend.ExchangeConfig{TokenURL: tokenURL, ClientID: "gangway"})

	if _, err := src.TokenFor(context.Background(), caller, "incoming"); err == nil {
		t.Error("want error on a network failure, got none")
	}
}

func TestExchangeRejectsInvalidTokenURL(t *testing.T) {
	// A control character in the URL makes request construction itself
	// fail, before any network call is attempted.
	src := backend.Exchange(backend.ExchangeConfig{TokenURL: "http://exchange.example/\n", ClientID: "gangway"})

	if _, err := src.TokenFor(context.Background(), caller, "incoming"); err == nil {
		t.Error("want error on an invalid token URL, got none")
	}
}

func TestExchangeRejectsMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	src := backend.Exchange(backend.ExchangeConfig{TokenURL: srv.URL, ClientID: "gangway"})

	if _, err := src.TokenFor(context.Background(), caller, "incoming"); err == nil {
		t.Error("want error on a malformed response body, got none")
	}
}

func TestExchangeRejectsResponseWithoutAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"bearer"}`))
	}))
	defer srv.Close()

	src := backend.Exchange(backend.ExchangeConfig{TokenURL: srv.URL, ClientID: "gangway"})

	if _, err := src.TokenFor(context.Background(), caller, "incoming"); err == nil {
		t.Error("want error when the provider returns no access_token, got none")
	}
}

func TestExchangeSendsScopeWhenSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if got := r.PostForm.Get("scope"); got != "read:things" {
			t.Errorf("scope = %q, want %q", got, "read:things")
		}
		if got := r.PostForm.Get("client_secret"); got != "" {
			t.Errorf("client_secret = %q, want empty (none configured)", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"exchanged-token"}`))
	}))
	defer srv.Close()

	src := backend.Exchange(backend.ExchangeConfig{TokenURL: srv.URL, ClientID: "gangway", Scope: "read:things"})

	if _, err := src.TokenFor(context.Background(), caller, "incoming"); err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
}

// TestPassThroughRejectsEmptyIncoming covers the error branch of
// PassThrough: with nothing to forward it must fail rather than silently
// hand back an empty credential.
func TestPassThroughRejectsEmptyIncoming(t *testing.T) {
	_, err := backend.PassThrough().TokenFor(context.Background(), caller, "")
	if err == nil {
		t.Error("want error when there is no incoming token to pass through, got none")
	}
}
