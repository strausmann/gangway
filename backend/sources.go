package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/strausmann/gangway/identity"
)

type staticToken struct{ token string }

// StaticToken uses one credential for every caller. Suitable when the
// service behind the server does not distinguish users.
func StaticToken(token string) TokenSource { return &staticToken{token: token} }

func (s *staticToken) TokenFor(context.Context, *identity.Identity, string) (string, error) {
	return s.token, nil
}

type perUser struct {
	lookup func(context.Context, *identity.Identity) (string, error)
}

// PerUser resolves a credential per caller. The lookup is where the
// server maps an identity onto its own account model.
func PerUser(lookup func(context.Context, *identity.Identity) (string, error)) TokenSource {
	return &perUser{lookup: lookup}
}

func (p *perUser) TokenFor(ctx context.Context, id *identity.Identity, _ string) (string, error) {
	return p.lookup(ctx, id)
}

type passThrough struct{}

// PassThrough forwards the caller's own token. Only correct when the
// service behind the server accepts tokens from the same issuer; needs a
// non-empty incoming (see TokenSource — serve.TokenFrom(ctx) is where a
// tool handler behind serve.Server gets one).
func PassThrough() TokenSource { return passThrough{} }

func (passThrough) TokenFor(_ context.Context, _ *identity.Identity, incoming string) (string, error) {
	if incoming == "" {
		return "", fmt.Errorf("gangway: no incoming token to pass through")
	}
	return incoming, nil
}

// ExchangeConfig configures RFC 8693 token exchange.
type ExchangeConfig struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	// Scope is optional.
	Scope string
	// Client is optional; a client with a timeout is used when nil.
	Client *http.Client
}

type exchange struct{ cfg ExchangeConfig }

// Exchange trades the caller's token for one the service accepts; like
// PassThrough, it needs a non-empty incoming (see TokenSource —
// serve.TokenFrom(ctx) is where a tool handler behind serve.Server gets
// one).
func Exchange(cfg ExchangeConfig) TokenSource {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	return &exchange{cfg: cfg}
}

func (e *exchange) TokenFor(ctx context.Context, _ *identity.Identity, incoming string) (string, error) {
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {incoming},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"client_id":          {e.cfg.ClientID},
	}
	if e.cfg.ClientSecret != "" {
		form.Set("client_secret", e.cfg.ClientSecret)
	}
	if e.cfg.Scope != "" {
		form.Set("scope", e.cfg.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.cfg.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gangway: token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// The body may echo the token — never include it in the error.
		return "", fmt.Errorf("gangway: token exchange rejected with status %d", resp.StatusCode)
	}

	var out struct {
		AccessToken string `json:"access_token"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("gangway: token exchange response not readable")
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("gangway: token exchange returned no access token")
	}
	return out.AccessToken, nil
}
