// Package serve assembles the building blocks into a running server.
package serve

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/strausmann/gangway/origin"
)

// minRemoteListInterval is the shortest refresh interval accepted from the
// environment. The origin package itself accepts any positive interval —
// its own tests need fast refreshes, and a direct caller knows what it is
// doing. A value read from the environment is unchecked input, though, and
// an accidentally tiny interval would hammer whoever publishes the
// allowlist with requests. The floor belongs here, not in origin.
const minRemoteListInterval = time.Minute

// Config holds every setting the server needs. All of it comes from the
// environment so credentials never sit in files.
type Config struct {
	Addr          string
	PublicBaseURL string

	// IssuerURL, Audience and SubjectClaim configure the default OIDC
	// verifier New builds when serve.WithVerifier is not used (see
	// resolveVerifier). LoadConfig reads them from the environment but,
	// deliberately, does not require IssuerURL or Audience to be set:
	// requiring them here too, in LoadConfig, forced every caller who
	// uses WithVerifier to also set two values it would then never
	// read. A caller who omits WithVerifier and leaves either empty
	// still fails to start — just at New's default branch (see
	// resolveVerifier), not at LoadConfig — and with the same
	// GANGWAY_ISSUER_URL/GANGWAY_AUDIENCE-naming an operator would have
	// seen from LoadConfig before: resolveVerifier checks both itself,
	// before calling identity.NewOIDC, specifically so that a missing
	// value is still named by its environment variable, not by the Go
	// field identity.NewOIDC's own (necessarily env-var-agnostic) check
	// would otherwise report.
	IssuerURL    string
	Audience     string
	SubjectClaim string

	HeaderMode      origin.HeaderMode
	TrustedProxies  []netip.Prefix
	AllowedPrefixes []netip.Prefix

	RemoteListURL      string
	RemoteListInterval time.Duration

	WritersClaim        string
	WritersValue        string
	AllowWriteByDefault bool

	// RequiredScopes lists the OAuth 2.0 scope values (RFC 6749 §3.3) a
	// connector needs to request when it signs in against IssuerURL. Both
	// discovery mechanisms RFC 9728 recognises advertise it once set: the
	// WWW-Authenticate challenge's "scope" parameter (see
	// Server.challenge) and the RFC 9728 metadata document's
	// scopes_supported field (see Handler). Left empty — the default —
	// neither is emitted and both stay exactly as they were before this
	// field existed: no scope in the challenge, no scopes_supported in
	// the document.
	//
	// Without it, a connector that only reads what gangway itself
	// advertises has no way to learn which scope to request and falls
	// back to whatever its own default is (often just "openid profile
	// offline_access") — that request succeeds, the sign-in appears to
	// complete, and the mismatch only surfaces later, at the first tool
	// call, as a token rejected for the wrong audience. Naming the scope
	// here lets the connector ask for the right one the first time.
	//
	// Every provider gangway has been deployed against so far — including
	// Authentik — uses this same short form on both ends: what a
	// connector requests and what ends up in the token's "scp" claim are
	// identical. Microsoft Entra ID is a documented exception (see
	// AdvertisedScopes below); RequiredScopes keeps meaning exactly what
	// it always has, because every other provider still needs it to.
	RequiredScopes []string

	// AdvertisedScopes, when set, overrides what the WWW-Authenticate
	// challenge's "scope" parameter (see Server.challenge) and the RFC
	// 9728 metadata document's scopes_supported field (see Handler)
	// advertise — RequiredScopes itself is untouched and keeps meaning
	// what its own doc comment says.
	//
	// This exists because the two are not always the same value. Entra ID
	// rejects a bare scope name in a token request with AADSTS650053 ("the
	// application asked for scope 'mcp.access' that doesn't exist on the
	// resource 'Microsoft Graph'") — a name with no resource prefix
	// resolves against the Microsoft Graph default resource, not this
	// server's own application. What Entra requires on the
	// request/advertisement side is the fully qualified
	// "api://<Application-ID-URI>/<scope-name>" form (see
	// https://learn.microsoft.com/en-us/azure/app-service/configure-authentication-mcp-server-vscode,
	// the WEBSITE_AUTH_PRM_DEFAULT_WITH_SCOPES setting), while the short
	// name is still what shows up in the token's "scp" claim afterwards.
	// Neither RFC 9728 nor RFC 6749/6750 mandates either shape — that is
	// squarely the authorization server's choice, and Entra's choice here
	// is the outlier among the providers this project has checked
	// (Authentik, Keycloak, Auth0, Okta and Cloudflare's OAuth provider
	// all use the same short name on both ends). A single field trying to
	// serve both purposes can only be correct for one kind of provider at
	// a time; this field exists so it does not have to choose.
	//
	// Left empty — the default, and the only value every deployment
	// before this field existed ever had — both the challenge and the
	// metadata document fall back to advertising RequiredScopes, exactly
	// as they did before this field existed. Setting it changes nothing
	// about what gangway itself checks: nothing in this package verifies
	// a token's "scp" claim against either field today (see RequiredScopes'
	// own value, unchanged, for what — if anything — a future check would
	// use).
	AdvertisedScopes []string
}

// LoadConfig reads the environment.
//
// It refuses to return a configuration that would leave the server open:
// a missing allowlist or public base URL is an error, not a default.
// Better to fail to start with a named cause than to come up wide open
// because a variable was forgotten.
//
// GANGWAY_ISSUER_URL and GANGWAY_AUDIENCE are read here but deliberately
// not validated here — see the comment on their fields in Config for why:
// the requirement to set them belongs to New's default OIDC verifier, not
// to LoadConfig itself, and used to live in both places at once.
//
// Error messages name the offending environment variable but never its
// value. Several of these variables are not meant to be echoed back —
// writer claim values, prefix lists — and startup failures end up in logs.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Addr:               envOr("GANGWAY_ADDR", ":8080"),
		PublicBaseURL:      os.Getenv("GANGWAY_PUBLIC_BASE_URL"),
		IssuerURL:          os.Getenv("GANGWAY_ISSUER_URL"),
		Audience:           os.Getenv("GANGWAY_AUDIENCE"),
		SubjectClaim:       envOr("GANGWAY_SUBJECT_CLAIM", "sub"),
		HeaderMode:         origin.HeaderMode(envOr("GANGWAY_CLIENT_IP_HEADER", string(origin.ModeXForwardedFor))),
		RemoteListURL:      os.Getenv("GANGWAY_REMOTE_LIST_URL"),
		RemoteListInterval: time.Hour,
		WritersClaim:       os.Getenv("GANGWAY_WRITERS_CLAIM"),
		WritersValue:       os.Getenv("GANGWAY_WRITERS_VALUE"),
	}

	if cfg.PublicBaseURL == "" {
		return nil, fmt.Errorf("gangway: GANGWAY_PUBLIC_BASE_URL is required")
	}

	switch cfg.HeaderMode {
	case origin.ModeXForwardedFor, origin.ModeXRealIP, origin.ModeCFConnectingIP:
	default:
		return nil, fmt.Errorf(
			"gangway: GANGWAY_CLIENT_IP_HEADER must be one of %q, %q, %q",
			origin.ModeXForwardedFor, origin.ModeXRealIP, origin.ModeCFConnectingIP)
	}

	var err error
	if cfg.AllowedPrefixes, err = parsePrefixes("GANGWAY_ALLOWED_PREFIXES", os.Getenv("GANGWAY_ALLOWED_PREFIXES")); err != nil {
		return nil, err
	}
	if cfg.TrustedProxies, err = parsePrefixes("GANGWAY_TRUSTED_PROXIES", os.Getenv("GANGWAY_TRUSTED_PROXIES")); err != nil {
		return nil, err
	}

	// Better not to run at all than to run wide open: no allowlist and no
	// remote source to fetch one from means every caller would be let in.
	if len(cfg.AllowedPrefixes) == 0 && cfg.RemoteListURL == "" {
		return nil, fmt.Errorf(
			"gangway: GANGWAY_ALLOWED_PREFIXES or GANGWAY_REMOTE_LIST_URL is required — " +
				"refusing to start without an allowlist")
	}

	if v := os.Getenv("GANGWAY_REMOTE_LIST_INTERVAL"); v != "" {
		d, parseErr := time.ParseDuration(v)
		if parseErr != nil {
			return nil, fmt.Errorf("gangway: GANGWAY_REMOTE_LIST_INTERVAL is not a valid duration")
		}
		if d < minRemoteListInterval {
			return nil, fmt.Errorf("gangway: GANGWAY_REMOTE_LIST_INTERVAL must be at least %s", minRemoteListInterval)
		}
		cfg.RemoteListInterval = d
	}

	if v := os.Getenv("GANGWAY_ALLOW_WRITE_BY_DEFAULT"); v != "" {
		b, parseErr := strconv.ParseBool(v)
		if parseErr != nil {
			return nil, fmt.Errorf("gangway: GANGWAY_ALLOW_WRITE_BY_DEFAULT is not a valid boolean")
		}
		cfg.AllowWriteByDefault = b
	}

	if cfg.RequiredScopes, err = parseScopes("GANGWAY_REQUIRED_SCOPES", os.Getenv("GANGWAY_REQUIRED_SCOPES")); err != nil {
		return nil, err
	}

	if cfg.AdvertisedScopes, err = parseScopes("GANGWAY_ADVERTISED_SCOPES", os.Getenv("GANGWAY_ADVERTISED_SCOPES")); err != nil {
		return nil, err
	}

	return cfg, nil
}

// envOr reads name from the environment, falling back to a default when it
// is unset or empty.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// parsePrefixes parses a comma-separated list of CIDR prefixes. On error it
// names the source variable and the position of the offending entry —
// never the entry's own text, since it came from an environment variable
// that may not be safe to log.
func parsePrefixes(name, value string) ([]netip.Prefix, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]netip.Prefix, 0, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("gangway: %s: entry %d is not a CIDR prefix", name, i+1)
		}
		out = append(out, p)
	}
	return out, nil
}

// isValidScopeToken reports whether s is a syntactically valid OAuth 2.0
// scope-token, as RFC 6749 §3.3 defines it:
//
//	scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
//
// — one or more characters in the printable ASCII range %x21-7E, except
// %x22 (the double quote) and %x5C (the backslash). That excludes space
// along with the two characters, which matters here for a second reason
// beyond spec conformance: parseScopes below and Server.challenge both
// treat a RequiredScopes entry as a single token — split apart by commas
// on the way in, rejoined with spaces on the way out (RFC 6750 §3's
// space-delimited "scope" parameter) — so a space inside one entry would
// silently turn one configured scope into two once a connector splits
// that parameter back apart. A double quote would instead break the
// quoted-string challenge wraps the joined list in.
func isValidScopeToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7E || r == 0x22 || r == 0x5C {
			return false
		}
	}
	return true
}

// parseScopes parses a comma-separated list of OAuth 2.0 scope values for
// GANGWAY_REQUIRED_SCOPES, in the same comma-separated, whitespace- and
// blank-entry-tolerant shape parsePrefixes accepts for the two CIDR-list
// variables above. Unlike parsePrefixes, the error message here has
// nothing sensitive to withhold — a scope name is not a secret — but it
// still names only the position of the offending entry, not its text, for
// consistency with every other rejection LoadConfig produces.
func parseScopes(name, value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !isValidScopeToken(part) {
			return nil, fmt.Errorf("gangway: %s: entry %d is not a valid OAuth 2.0 scope token", name, i+1)
		}
		out = append(out, part)
	}
	return out, nil
}
