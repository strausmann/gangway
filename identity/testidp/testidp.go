// Package testidp provides a minimal OpenID Connect issuer for tests.
// It generates its own key pair, serves a discovery document and a JWKS
// endpoint, and signs tokens on demand. No network access required.
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type IDP struct {
	srv *httptest.Server

	mu          sync.RWMutex
	key         *rsa.PrivateKey
	keyID       string
	unavailable bool
}

// New starts a test issuer and registers cleanup with t.
func New(t *testing.T) *IDP {
	t.Helper()

	i := &IDP{}
	i.newKey()

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", i.handleDiscovery)
	mux.HandleFunc("/keys", i.handleKeys)

	i.srv = httptest.NewServer(mux)
	t.Cleanup(i.srv.Close)
	return i
}

func (i *IDP) newKey() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err) // only reachable if the system entropy source fails
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.key = key
	i.keyID = time.Now().Format("20060102150405.000000000")
}

// Rotate replaces the key pair. Tokens issued before remain syntactically
// valid but no longer verify — this is how key rollover is tested.
func (i *IDP) Rotate() { i.newKey() }

func (i *IDP) URL() string { return i.srv.URL }

// SetUnavailable makes both the discovery and keys endpoints respond with
// 503 Service Unavailable while true, simulating a transient outage at the
// identity provider. Used to test that a verifier's background key refresh
// tolerates a failed rediscovery attempt instead of being disturbed by it.
func (i *IDP) SetUnavailable(unavailable bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.unavailable = unavailable
}

func (i *IDP) isUnavailable() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.unavailable
}

func (i *IDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	if i.isUnavailable() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                i.srv.URL,
		"jwks_uri":                              i.srv.URL + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (i *IDP) handleKeys(w http.ResponseWriter, _ *http.Request) {
	if i.isUnavailable() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       i.key.Public(),
		KeyID:     i.keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

// Token signs the given claims. Callers set iss, aud, exp and sub
// themselves so that invalid combinations can be tested.
func (i *IDP) Token(claims map[string]any) string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: i.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", i.keyID),
	)
	if err != nil {
		panic(err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return tok
}
