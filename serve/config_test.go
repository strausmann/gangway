package serve_test

import (
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

func TestLoadConfigRefusesMissingIssuer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_ISSUER_URL", "")

	if _, err := serve.LoadConfig(); err == nil {
		t.Error("want an error when the issuer is missing, got none")
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

func TestLoadConfigRefusesMissingAudience(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GANGWAY_AUDIENCE", "")

	_, err := serve.LoadConfig()
	if err == nil {
		t.Fatal("want an error when the audience is missing, got none")
	}
	if !strings.Contains(err.Error(), "GANGWAY_AUDIENCE") {
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
