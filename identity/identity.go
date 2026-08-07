// Package identity verifies bearer tokens against an OpenID Connect issuer.
//
// No provider-specific code exists here. Entra ID, Authentik, Keycloak,
// Auth0 and Google differ only in configuration: issuer URL, expected
// audience, and which claim carries the stable subject.
package identity

import (
	"context"
	"errors"
)

// ErrUnauthenticated is returned for every rejected token. The reason is
// deliberately not exposed to callers — it belongs in logs, not in
// responses.
var ErrUnauthenticated = errors.New("gangway: unauthenticated")

// Identity is a verified caller.
type Identity struct {
	// Subject is the value of the configured subject claim.
	Subject string
	// Claims holds all verified claims, for authorization decisions.
	Claims map[string]any
}

// Verifier turns a raw bearer token into a verified Identity.
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*Identity, error)
}
