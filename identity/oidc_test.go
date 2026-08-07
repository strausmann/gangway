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
	v, err := identity.NewOIDC(context.Background(), identity.OIDCConfig{
		IssuerURL:    idp.URL(),
		Audience:     "test-audience",
		SubjectClaim: subjectClaim,
	})
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

func TestRejectsAfterKeyRotation(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifier(t, idp, "sub")

	token := idp.Token(validClaims(idp))
	idp.Rotate()

	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Error("token signed with the retired key was accepted")
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
