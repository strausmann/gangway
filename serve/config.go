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
