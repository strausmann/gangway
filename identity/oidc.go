package identity

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCConfig configures verification. All three fields are required.
type OIDCConfig struct {
	// IssuerURL is the issuer, without the well-known suffix.
	IssuerURL string
	// Audience is the value the token's aud claim must contain.
	Audience string
	// SubjectClaim names the claim used as the stable identifier.
	// Use "sub" unless the provider pseudonymises it — Entra ID does,
	// where "oid" is the tenant-stable choice.
	SubjectClaim string
}

type oidcVerifier struct {
	verifier     *oidc.IDTokenVerifier
	subjectClaim string
}

// NewOIDC fetches the issuer's discovery document and returns a Verifier.
// It fails if the issuer cannot be reached — a server that cannot verify
// anyone should not start.
func NewOIDC(ctx context.Context, cfg OIDCConfig) (Verifier, error) {
	switch {
	case cfg.IssuerURL == "":
		return nil, fmt.Errorf("gangway: IssuerURL is required")
	case cfg.Audience == "":
		return nil, fmt.Errorf("gangway: Audience is required")
	case cfg.SubjectClaim == "":
		return nil, fmt.Errorf("gangway: SubjectClaim is required")
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("gangway: discover issuer %s: %w", cfg.IssuerURL, err)
	}

	return &oidcVerifier{
		verifier:     provider.Verifier(&oidc.Config{ClientID: cfg.Audience}),
		subjectClaim: cfg.SubjectClaim,
	}, nil
}

func (v *oidcVerifier) Verify(ctx context.Context, rawToken string) (*Identity, error) {
	tok, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}

	claims := map[string]any{}
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims not readable", ErrUnauthenticated)
	}

	subject, ok := claims[v.subjectClaim].(string)
	if !ok || subject == "" {
		return nil, fmt.Errorf("%w: claim %q missing or not a string",
			ErrUnauthenticated, v.subjectClaim)
	}

	return &Identity{Subject: subject, Claims: claims}, nil
}
