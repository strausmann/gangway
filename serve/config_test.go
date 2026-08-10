package serve_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/strausmann/gangway/serve"
)

func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "https://mcp.example.com")
	t.Setenv("GANGWAY_ISSUER_URL", "https://id.example.com/application/o/mcp/")
	t.Setenv("GANGWAY_AUDIENCE", "mcp-server")
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "160.79.104.0/21")
	t.Setenv("GANGWAY_TRUSTED_PROXIES", "172.16.0.0/12")
}

func TestLoadConfigAcceptsMinimalSetup(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SubjectClaim != "sub" {
		t.Errorf("SubjectClaim = %q, want the default %q", cfg.SubjectClaim, "sub")
	}
	if len(cfg.AllowedPrefixes) != 1 {
		t.Errorf("got %d allowed prefixes, want 1", len(cfg.AllowedPrefixes))
	}
}

func TestLoadConfigRefusesMissingAllowlist(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "")

	// A server that would let everyone in must not start.
	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error when the allowlist is missing, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_ALLOWED_PREFIXES") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

// TestLoadConfigNoLongerRequiresIssuerOrAudience is the regression test
// for the finding that LoadConfig used to enforce GANGWAY_ISSUER_URL and
// GANGWAY_AUDIENCE even for a caller who uses serve.WithVerifier and
// never reads either — see Config's field comment. Both are read into
// the Config as-is, empty or not; LoadConfig itself no longer refuses
// either being empty. serve/serve_test.go carries the complementary
// proof that a caller who omits both WithVerifier and these two values
// still fails to start, just one layer later, at serve.New — this test
// only covers LoadConfig's own, narrower contract.
func TestLoadConfigNoLongerRequiresIssuerOrAudience(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ISSUER_URL", "")
	t.Setenv("GANGWAY_AUDIENCE", "")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.IssuerURL != "" {
		t.Errorf("IssuerURL = %q, want empty", cfg.IssuerURL)
	}
	if cfg.Audience != "" {
		t.Errorf("Audience = %q, want empty", cfg.Audience)
	}
}

func TestLoadConfigRefusesUnknownHeaderMode(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_CLIENT_IP_HEADER", "x-my-own-header")

	if _, err := serve.LoadConfig(); err == nil {
		t.Error("want an error for an unknown header mode, got none")
	}
}

func TestLoadConfigRefusesMalformedPrefix(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "160.79.104.1") // address, not a prefix

	if _, err := serve.LoadConfig(); err == nil {
		t.Error("want an error for a malformed prefix, got none")
	}
}

// --- Coverage for the remaining paths ---

func TestLoadConfigRefusesMissingPublicBaseURL(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_PUBLIC_BASE_URL", "")

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error when the public base URL is missing, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_PUBLIC_BASE_URL") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}

func TestLoadConfigRefusesMalformedTrustedProxies(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_TRUSTED_PROXIES", "not-a-prefix")

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error for a malformed trusted proxy entry, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_TRUSTED_PROXIES") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

func TestLoadConfigAllowsRemoteListWithoutAllowedPrefixes(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", "")
	t.Setenv("GANGWAY_REMOTE_LIST_URL", "https://list.example.com/prefixes.txt")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.AllowedPrefixes) != 0 {
		t.Errorf("got %d allowed prefixes, want 0 (list comes from the remote source)", len(cfg.AllowedPrefixes))
	}
	if cfg.RemoteListURL == "" {
		t.Error("RemoteListURL was not carried into the config")
	}
}

func TestLoadConfigParsesMultiplePrefixesWithWhitespaceAndBlanks(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ALLOWED_PREFIXES", " 160.79.104.0/21 , ,10.0.0.0/8")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.AllowedPrefixes) != 2 {
		t.Errorf("got %d allowed prefixes, want 2", len(cfg.AllowedPrefixes))
	}
}

func TestLoadConfigDefaultsAddrAndRemoteListInterval(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Addr != ":8080" {
		t.Errorf("Addr = %q, want the default %q", cfg.Addr, ":8080")
	}
	if cfg.RemoteListInterval.String() != "1h0m0s" {
		t.Errorf("RemoteListInterval = %v, want the default 1h", cfg.RemoteListInterval)
	}
}

func TestLoadConfigOverridesAddr(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ADDR", "127.0.0.1:9090")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Addr != "127.0.0.1:9090" {
		t.Errorf("Addr = %q, want %q", cfg.Addr, "127.0.0.1:9090")
	}
}

func TestLoadConfigOverridesSubjectClaim(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_SUBJECT_CLAIM", "email")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SubjectClaim != "email" {
		t.Errorf("SubjectClaim = %q, want %q", cfg.SubjectClaim, "email")
	}
}

func TestLoadConfigAcceptsEveryKnownHeaderMode(t *testing.T) {
	modes := []string{"x-forwarded-for", "x-real-ip", "cf-connecting-ip"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			setMinimalEnv(t)
			t.Setenv("GANGWAY_CLIENT_IP_HEADER", mode)

			cfg, err := serve.LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if string(cfg.HeaderMode) != mode {
				t.Errorf("HeaderMode = %q, want %q", cfg.HeaderMode, mode)
			}
		})
	}
}

func TestLoadConfigOverridesRemoteListInterval(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_REMOTE_LIST_INTERVAL", "5m")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.RemoteListInterval.String() != "5m0s" {
		t.Errorf("RemoteListInterval = %v, want 5m", cfg.RemoteListInterval)
	}
}

func TestLoadConfigRefusesMalformedRemoteListInterval(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_REMOTE_LIST_INTERVAL", "not-a-duration")

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error for a malformed interval, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_REMOTE_LIST_INTERVAL") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

// TestLoadConfigRefusesRemoteListIntervalBelowOneMinute belongs to this task's
// addition beyond the excerpt: the library itself accepts any positive
// interval (its tests need fast refreshes), but a value read from the
// environment is unchecked input. An accidentally tiny interval would
// hammer whoever publishes the allowlist, so anything under a minute is
// refused at startup.
func TestLoadConfigRefusesRemoteListIntervalBelowOneMinute(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_REMOTE_LIST_INTERVAL", "30s")

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error for an interval below one minute, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_REMOTE_LIST_INTERVAL") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

func TestLoadConfigAcceptsRemoteListIntervalAtExactlyOneMinute(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_REMOTE_LIST_INTERVAL", "1m")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.RemoteListInterval.String() != "1m0s" {
		t.Errorf("RemoteListInterval = %v, want 1m", cfg.RemoteListInterval)
	}
}

func TestLoadConfigParsesAllowWriteByDefault(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		t.Run(value, func(t *testing.T) {
			setMinimalEnv(t)
			t.Setenv("GANGWAY_ALLOW_WRITE_BY_DEFAULT", value)

			cfg, err := serve.LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if want := value == "true"; cfg.AllowWriteByDefault != want {
				t.Errorf("AllowWriteByDefault = %v, want %v", cfg.AllowWriteByDefault, want)
			}
		})
	}
}

func TestLoadConfigRefusesMalformedAllowWriteByDefault(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ALLOW_WRITE_BY_DEFAULT", "maybe")

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error for a malformed boolean, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_ALLOW_WRITE_BY_DEFAULT") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

// --- GANGWAY_REQUIRED_SCOPES ---

func TestLoadConfigDefaultsRequiredScopesToEmpty(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.RequiredScopes) != 0 {
		t.Errorf("RequiredScopes = %v, want none", cfg.RequiredScopes)
	}
}

func TestLoadConfigParsesRequiredScopes(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_REQUIRED_SCOPES", "mcp.access")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !slices.Equal(cfg.RequiredScopes, []string{"mcp.access"}) {
		t.Errorf("RequiredScopes = %v, want [%q]", cfg.RequiredScopes, "mcp.access")
	}
}

func TestLoadConfigParsesMultipleRequiredScopesWithWhitespaceAndBlanks(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_REQUIRED_SCOPES", " mcp.access , ,offline_access")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !slices.Equal(cfg.RequiredScopes, []string{"mcp.access", "offline_access"}) {
		t.Errorf("RequiredScopes = %v, want [%q %q]", cfg.RequiredScopes, "mcp.access", "offline_access")
	}
}

// TestLoadConfigRefusesRequiredScopeContainingASpace is the regression
// test for the reason RequiredScopes is validated at all: RFC 6749 §3.3
// defines a scope-token as excluding space, and Server.challenge below
// joins RequiredScopes with a single space to build the WWW-Authenticate
// "scope" parameter. An entry that itself contained a space would
// silently turn one configured scope into two once a connector splits
// that parameter back apart — the same failure mode the missing scope
// advertisement this task fixes was caused by, just self-inflicted
// instead of upstream. Rejecting it at startup, named, is cheaper than
// debugging a connector that parses the challenge "correctly" and still
// requests the wrong scope.
func TestLoadConfigRefusesRequiredScopeContainingASpace(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_REQUIRED_SCOPES", "mcp access")

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error for a scope containing a space, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_REQUIRED_SCOPES") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

// TestLoadConfigRefusesRequiredScopeContainingADoubleQuote is the
// regression test for the other half of the same reason: the challenge
// wraps RequiredScopes in a quoted-string (`scope="..."`). A scope value
// containing an unescaped double quote would terminate that quoted-string
// early and corrupt the WWW-Authenticate header for every caller, not
// just the one connector that happened to request it — RFC 6749 §3.3
// excludes the double quote from scope-token for exactly this reason.
func TestLoadConfigRefusesRequiredScopeContainingADoubleQuote(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_REQUIRED_SCOPES", `mcp."access`)

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error for a scope containing a double quote, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_REQUIRED_SCOPES") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

// TestLoadConfigAcceptsARequiredScopeWithURNStyleColonsAndSlashes documents
// the other end of the same boundary: scope-token's allowed range
// (%x21 / %x23-5B / %x5D-7E) is far wider than the alphanumeric-dot names
// used elsewhere in this file's tests — colons, slashes and dots are all
// inside it, which is what lets URN- or URL-shaped scopes (as several
// real providers issue, e.g. "urn:mcp:access") through unmodified.
func TestLoadConfigAcceptsARequiredScopeWithURNStyleColonsAndSlashes(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_REQUIRED_SCOPES", "urn:mcp:access,https://example.com/mcp.read")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := []string{"urn:mcp:access", "https://example.com/mcp.read"}
	if !slices.Equal(cfg.RequiredScopes, want) {
		t.Errorf("RequiredScopes = %v, want %v", cfg.RequiredScopes, want)
	}
}

// --- GANGWAY_ADVERTISED_SCOPES ---

func TestLoadConfigDefaultsAdvertisedScopesToEmpty(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.AdvertisedScopes) != 0 {
		t.Errorf("AdvertisedScopes = %v, want none", cfg.AdvertisedScopes)
	}
}

func TestLoadConfigParsesAdvertisedScopes(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ADVERTISED_SCOPES", "api://11111111-2222-3333-4444-555555555555/mcp.access")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := []string{"api://11111111-2222-3333-4444-555555555555/mcp.access"}
	if !slices.Equal(cfg.AdvertisedScopes, want) {
		t.Errorf("AdvertisedScopes = %v, want %v", cfg.AdvertisedScopes, want)
	}
}

func TestLoadConfigParsesMultipleAdvertisedScopesWithWhitespaceAndBlanks(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ADVERTISED_SCOPES", " api://app-id/mcp.access , ,api://app-id/offline_access")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := []string{"api://app-id/mcp.access", "api://app-id/offline_access"}
	if !slices.Equal(cfg.AdvertisedScopes, want) {
		t.Errorf("AdvertisedScopes = %v, want %v", cfg.AdvertisedScopes, want)
	}
}

// TestLoadConfigRefusesAdvertisedScopeContainingASpace mirrors
// TestLoadConfigRefusesRequiredScopeContainingASpace: AdvertisedScopes goes
// through the identical isValidScopeToken check RequiredScopes does, and
// Server.challenge joins it with a single space the same way — an entry
// that itself contained a space would silently turn one configured scope
// into two once a connector splits the "scope" auth-param back apart.
func TestLoadConfigRefusesAdvertisedScopeContainingASpace(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ADVERTISED_SCOPES", "api://app-id/mcp access")

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error for an advertised scope containing a space, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_ADVERTISED_SCOPES") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

// TestLoadConfigRefusesAdvertisedScopeContainingADoubleQuote mirrors
// TestLoadConfigRefusesRequiredScopeContainingADoubleQuote: the challenge
// wraps AdvertisedScopes in a quoted-string the same way it does
// RequiredScopes, so an unescaped double quote would corrupt the
// WWW-Authenticate header the same way.
func TestLoadConfigRefusesAdvertisedScopeContainingADoubleQuote(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ADVERTISED_SCOPES", `api://app-id/mcp."access`)

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error for an advertised scope containing a double quote, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_ADVERTISED_SCOPES") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

// TestLoadConfigAcceptsAFullyQualifiedEntraStyleAdvertisedScope is the
// reason AdvertisedScopes exists at all: Entra ID rejects a bare scope
// name like "mcp.access" in a token request with AADSTS650053 ("scope ...
// that doesn't exist on the resource 'Microsoft Graph'") because a name
// without a resource prefix resolves against Graph, not this server's own
// application. What must be requested/advertised there is the fully
// qualified "api://<Application-ID-URI>/<scope-name>" form (see
// https://learn.microsoft.com/en-us/azure/app-service/configure-authentication-mcp-server-vscode,
// WEBSITE_AUTH_PRM_DEFAULT_WITH_SCOPES) while the token's "scp" claim still
// carries only the short name — the exact split AdvertisedScopes and
// RequiredScopes now model. isValidScopeToken already allows ":" and "/"
// (see TestLoadConfigAcceptsARequiredScopeWithURNStyleColonsAndSlashes for
// the same boundary on RequiredScopes); this test pins the specific
// Entra-shaped value down so a future change to that boundary cannot
// silently break it.
func TestLoadConfigAcceptsAFullyQualifiedEntraStyleAdvertisedScope(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ADVERTISED_SCOPES", "api://11111111-2222-3333-4444-555555555555/mcp.access")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := []string{"api://11111111-2222-3333-4444-555555555555/mcp.access"}
	if !slices.Equal(cfg.AdvertisedScopes, want) {
		t.Errorf("AdvertisedScopes = %v, want %v", cfg.AdvertisedScopes, want)
	}
}

func TestLoadConfigCarriesWritersClaimAndValue(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_WRITERS_CLAIM", "groups")
	t.Setenv("GANGWAY_WRITERS_VALUE", "mcp-writers")

	cfg, err := serve.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.WritersClaim != "groups" {
		t.Errorf("WritersClaim = %q, want %q", cfg.WritersClaim, "groups")
	}
	if cfg.WritersValue != "mcp-writers" {
		t.Errorf("WritersValue = %q, want %q", cfg.WritersValue, "mcp-writers")
	}
}

// TestLoadConfigErrorsNeverContainTheOffendingValue guards against the
// startup errors leaking configuration values into logs. Several of the
// checked variables are the kind of thing an operator would not want to
// see echoed back — writer claim values, prefix lists, and the like — so
// every rejection is checked for the exact string that was set, not just
// for "an error happened".
func TestLoadConfigErrorsNeverContainTheOffendingValue(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		value  string
		secret string // the exact substring that must never appear in the error
	}{
		{
			name:   "unknown header mode",
			env:    "GANGWAY_CLIENT_IP_HEADER",
			value:  "x-shibboleet-secret-header",
			secret: "x-shibboleet-secret-header",
		},
		{
			name:   "malformed allowed prefix",
			env:    "GANGWAY_ALLOWED_PREFIXES",
			value:  "definitely-not-a-cidr-9f8e7d6c",
			secret: "9f8e7d6c",
		},
		{
			name:   "malformed trusted proxy",
			env:    "GANGWAY_TRUSTED_PROXIES",
			value:  "definitely-not-a-cidr-1a2b3c4d",
			secret: "1a2b3c4d",
		},
		{
			name:   "malformed remote list interval",
			env:    "GANGWAY_REMOTE_LIST_INTERVAL",
			value:  "not-a-duration-5e6f7a8b",
			secret: "5e6f7a8b",
		},
		{
			name:   "malformed allow-write-by-default",
			env:    "GANGWAY_ALLOW_WRITE_BY_DEFAULT",
			value:  "not-a-bool-9c8d7e6f",
			secret: "9c8d7e6f",
		},
		{
			name:   "invalid required scope",
			env:    "GANGWAY_REQUIRED_SCOPES",
			value:  "not a valid scope-7b6a5c4d",
			secret: "7b6a5c4d",
		},
		{
			name:   "invalid advertised scope",
			env:    "GANGWAY_ADVERTISED_SCOPES",
			value:  "not a valid scope-3e2d1c0b",
			secret: "3e2d1c0b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setMinimalEnv(t)
			t.Setenv(tt.env, tt.value)

			_, err := serve.LoadConfig()
			if err == nil {
				t.Fatal("want an error, got none")
			}
			if strings.Contains(err.Error(), tt.secret) {
				t.Errorf("error %q leaks the offending value %q", err, tt.secret)
			}
		})
	}
}
