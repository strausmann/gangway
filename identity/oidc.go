package identity

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// defaultKeyRefreshInterval is used when OIDCConfig.KeyRefreshInterval is
// left at its zero value.
const defaultKeyRefreshInterval = 15 * time.Minute

// OIDCConfig configures verification. IssuerURL, Audience and SubjectClaim
// are required.
type OIDCConfig struct {
	// IssuerURL is the issuer, without the well-known suffix.
	IssuerURL string
	// Audience is the value the token's aud claim must contain.
	Audience string
	// SubjectClaim names the claim used as the stable identifier.
	// Use "sub" unless the provider pseudonymises it — Entra ID does,
	// where "oid" is the tenant-stable choice.
	SubjectClaim string

	// KeyRefreshInterval controls how often the issuer's signing keys are
	// fetched again. Without this, a key rotation at the provider does not
	// reach a long-running verifier: the underlying key set only refetches
	// for key IDs it has never seen, so a stolen key stays usable until the
	// process restarts.
	//
	// Defaults to 15 minutes. Set to a negative value to disable refreshing
	// (not recommended outside tests).
	KeyRefreshInterval time.Duration
}

type oidcVerifier struct {
	mu           sync.RWMutex
	verifier     *oidc.IDTokenVerifier
	subjectClaim string
}

// NewOIDC fetches the issuer's discovery document and returns a Verifier.
// It fails if the issuer cannot be reached — a server that cannot verify
// anyone should not start.
//
// ctx does more than bound the initial discovery call: unless
// OIDCConfig.KeyRefreshInterval is negative, ctx also governs the lifetime
// of the background key-refresh loop (see OIDCConfig.KeyRefreshInterval).
// The loop stops as soon as ctx is done, and the verifier is then
// permanently stuck with whatever keys it had cached at that point. Pass a
// context whose lifetime matches the server's — not a short-lived
// request-scoped context — or refreshing silently never happens again.
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

	v := &oidcVerifier{
		verifier:     provider.Verifier(&oidc.Config{ClientID: cfg.Audience}),
		subjectClaim: cfg.SubjectClaim,
	}

	if cfg.KeyRefreshInterval >= 0 {
		interval := cfg.KeyRefreshInterval
		if interval == 0 {
			interval = defaultKeyRefreshInterval
		}
		go v.refreshKeys(ctx, cfg, interval)
	}

	return v, nil
}

// refreshKeys periodically rediscovers the issuer and swaps in a verifier
// built from the freshly fetched signing keys, dropping any retired key
// that the previous verifier still trusted. It runs until ctx is done.
//
// A failed discovery attempt (the issuer briefly unreachable) leaves the
// current verifier in place and is retried on the next tick — a transient
// outage at the identity provider must not stop already-issued, still-valid
// tokens from verifying.
func (v *oidcVerifier) refreshKeys(ctx context.Context, cfg OIDCConfig, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
			if err != nil {
				continue
			}
			v.setVerifier(provider.Verifier(&oidc.Config{ClientID: cfg.Audience}))
		}
	}
}

func (v *oidcVerifier) currentVerifier() *oidc.IDTokenVerifier {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.verifier
}

func (v *oidcVerifier) setVerifier(iv *oidc.IDTokenVerifier) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.verifier = iv
}

func (v *oidcVerifier) Verify(ctx context.Context, rawToken string) (*Identity, error) {
	tok, err := v.currentVerifier().Verify(ctx, rawToken)
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
