package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/strausmann/gangway/identity"
	"github.com/strausmann/gangway/identity/testidp"
)

func newVerifier(t *testing.T, idp *testidp.IDP, subjectClaim string) identity.Verifier {
	t.Helper()
	return newVerifierWithConfig(t, identity.OIDCConfig{
		IssuerURL:    idp.URL(),
		Audience:     "test-audience",
		SubjectClaim: subjectClaim,
	})
}

func newVerifierWithConfig(t *testing.T, cfg identity.OIDCConfig) identity.Verifier {
	t.Helper()
	// t.Context() is cancelled when the test ends, which stops the
	// background key-refresh goroutine started by NewOIDC instead of
	// leaking it for the lifetime of the test binary.
	v, err := identity.NewOIDC(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	return v
}

func validClaims(idp *testidp.IDP) map[string]any {
	return map[string]any{
		"iss": idp.URL(),
		"aud": "test-audience",
		"sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

func TestAcceptsValidToken(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifier(t, idp, "sub")

	id, err := v.Verify(context.Background(), idp.Token(validClaims(idp)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Subject != "user-123" {
		t.Errorf("Subject = %q, want %q", id.Subject, "user-123")
	}
}

func TestRejectsWrongAudience(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifier(t, idp, "sub")

	claims := validClaims(idp)
	claims["aud"] = "someone-else"

	if _, err := v.Verify(context.Background(), idp.Token(claims)); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Errorf("err = %v, want ErrUnauthenticated", err)
	}
}

func TestRejectsExpiredToken(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifier(t, idp, "sub")

	claims := validClaims(idp)
	claims["exp"] = time.Now().Add(-time.Minute).Unix()

	if _, err := v.Verify(context.Background(), idp.Token(claims)); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Errorf("err = %v, want ErrUnauthenticated", err)
	}
}

func TestRejectsForeignIssuer(t *testing.T) {
	ours := testidp.New(t)
	foreign := testidp.New(t)
	v := newVerifier(t, ours, "sub")

	// Signed by a different issuer with its own key, but claiming to be ours.
	claims := validClaims(ours)
	if _, err := v.Verify(context.Background(), foreign.Token(claims)); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Errorf("err = %v, want ErrUnauthenticated", err)
	}
}

func TestUsesConfiguredSubjectClaim(t *testing.T) {
	idp := testidp.New(t)
	// Entra pseudonymises "sub" per application; "oid" is stable per tenant.
	v := newVerifier(t, idp, "oid")

	claims := validClaims(idp)
	claims["oid"] = "tenant-stable-id"

	id, err := v.Verify(context.Background(), idp.Token(claims))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Subject != "tenant-stable-id" {
		t.Errorf("Subject = %q, want %q", id.Subject, "tenant-stable-id")
	}
}

// TestRejectsUnknownKeyID covers the cold case: a verifier that has never
// seen this issuer's keys before. The underlying key set fetches once, on
// first use, and only ever sees the post-rotation key set — so the token
// signed with the retired key is rejected immediately, without needing any
// key refresh. This must not be confused with TestRejectsAfterKeyRotation
// below, which covers the warm cache instead.
func TestRejectsUnknownKeyID(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifier(t, idp, "sub")

	token := idp.Token(validClaims(idp))
	idp.Rotate()

	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Error("token signed with the retired key was accepted")
	}
}

// TestRejectsAfterKeyRotation covers the realistic case: a long-running
// verifier that has already cached the issuer's current signing key before
// rotation happens. The underlying key set (coreos/go-oidc's RemoteKeySet)
// only re-fetches keys for a key ID it has never seen — a previously seen
// key ID keeps verifying against the stale cached key forever, even after
// the provider retires it. Confirmed against the RemoteKeySet source
// (github.com/coreos/go-oidc/v3/oidc/jwks.go, verify()) and by the inverse
// experiment: without OIDCConfig.KeyRefreshInterval driving a periodic
// rediscovery, this exact sequence keeps accepting the retired-key token.
//
// A very short KeyRefreshInterval is configured here so the background
// refresh loop rediscovers the issuer (and therefore drops the retired key)
// within the test's lifetime. The retry loop below has no fixed sleep
// before asserting rejection, because the refresh happens on a ticker in a
// separate goroutine — asserting immediately would be racy, and a fixed
// sleep would make the test slow or flaky depending on scheduling.
func TestRejectsAfterKeyRotation(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifierWithConfig(t, identity.OIDCConfig{
		IssuerURL:          idp.URL(),
		Audience:           "test-audience",
		SubjectClaim:       "sub",
		KeyRefreshInterval: 20 * time.Millisecond,
	})

	token := idp.Token(validClaims(idp))

	// Warm the cache: this Verify call is what makes the scenario
	// realistic. Without it, the key ID would still be unknown to the
	// verifier and TestRejectsUnknownKeyID's cold-case behaviour would
	// apply instead.
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify (before rotation): %v", err)
	}

	idp.Rotate()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := v.Verify(context.Background(), token); err != nil {
			return // rejected, as required
		}
		if time.Now().After(deadline) {
			t.Fatal("token signed with the retired key was still accepted after the refresh interval elapsed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRecoversAfterProviderOutage exercises the failure branch of the
// background key-refresh loop directly: a rediscovery attempt that fails
// while the issuer is briefly unreachable must not disturb the verifier
// currently in use, and refreshing must resume once the issuer is reachable
// again. If a failed attempt instead cleared the verifier, or if the
// refresh loop gave up retrying after one failure, a transient hiccup at
// the identity provider would silently and permanently break verification
// for the lifetime of the process — exactly the outage the refreshKeys
// retry-on-error branch exists to prevent.
func TestRecoversAfterProviderOutage(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifierWithConfig(t, identity.OIDCConfig{
		IssuerURL:          idp.URL(),
		Audience:           "test-audience",
		SubjectClaim:       "sub",
		KeyRefreshInterval: 20 * time.Millisecond,
	})

	token := idp.Token(validClaims(idp))
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify (before outage): %v", err)
	}

	idp.SetUnavailable(true)
	// There is no externally observable signal for "a refresh attempt just
	// failed" (that's the point: it must be invisible to callers), so this
	// waits out several refresh intervals to let multiple attempts fail
	// before asserting the verifier survived them.
	time.Sleep(5 * 20 * time.Millisecond)

	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify (during outage): a failed refresh attempt disturbed the existing verifier: %v", err)
	}

	idp.SetUnavailable(false)
	idp.Rotate()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := v.Verify(context.Background(), token); err != nil {
			return // the refresh loop recovered and picked up the new key set
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh loop did not recover after the provider outage ended")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestKeyRefreshCanBeDisabled documents and covers the escape hatch: a
// negative KeyRefreshInterval disables the background refresh loop
// entirely. This is the opposite of the security property under test
// above and exists for tests/tools that want a fully deterministic
// verifier with no background goroutine — never for production use.
func TestKeyRefreshCanBeDisabled(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifierWithConfig(t, identity.OIDCConfig{
		IssuerURL:          idp.URL(),
		Audience:           "test-audience",
		SubjectClaim:       "sub",
		KeyRefreshInterval: -1,
	})

	if _, err := v.Verify(context.Background(), idp.Token(validClaims(idp))); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestNewOIDCRequiresIssuerURL(t *testing.T) {
	_, err := identity.NewOIDC(context.Background(), identity.OIDCConfig{
		Audience:     "test-audience",
		SubjectClaim: "sub",
	})
	if err == nil {
		t.Error("NewOIDC accepted a config without IssuerURL")
	}
}

func TestNewOIDCRequiresAudience(t *testing.T) {
	idp := testidp.New(t)
	_, err := identity.NewOIDC(context.Background(), identity.OIDCConfig{
		IssuerURL:    idp.URL(),
		SubjectClaim: "sub",
	})
	if err == nil {
		t.Error("NewOIDC accepted a config without Audience")
	}
}

func TestNewOIDCRequiresSubjectClaim(t *testing.T) {
	idp := testidp.New(t)
	_, err := identity.NewOIDC(context.Background(), identity.OIDCConfig{
		IssuerURL: idp.URL(),
		Audience:  "test-audience",
	})
	if err == nil {
		t.Error("NewOIDC accepted a config without SubjectClaim")
	}
}

func TestNewOIDCFailsOnUnreachableIssuer(t *testing.T) {
	// Port 1 is reserved and nothing listens there, so the connection is
	// refused immediately instead of waiting on a DNS/dial timeout.
	_, err := identity.NewOIDC(context.Background(), identity.OIDCConfig{
		IssuerURL:    "http://127.0.0.1:1",
		Audience:     "test-audience",
		SubjectClaim: "sub",
	})
	if err == nil {
		t.Error("NewOIDC accepted an unreachable issuer")
	}
}

func TestRejectsMissingSubjectClaim(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifier(t, idp, "missing-claim")

	if _, err := v.Verify(context.Background(), idp.Token(validClaims(idp))); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Errorf("err = %v, want ErrUnauthenticated", err)
	}
}
