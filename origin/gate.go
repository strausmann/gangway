package origin

import (
	"context"
	"net/http"
	"net/netip"
)

type ctxKey struct{}

// AddrFrom returns the verified client address placed into the context by
// Gate.
func AddrFrom(ctx context.Context) (netip.Addr, bool) {
	addr, ok := ctx.Value(ctxKey{}).(netip.Addr)
	return addr, ok
}

// GateConfig configures the allowlist middleware.
type GateConfig struct {
	// Allow decides which addresses may reach the server.
	Allow List
	// Trusted lists the networks whose forwarding headers are believed.
	// Leave empty when no proxy is in front — then only the peer counts.
	Trusted []netip.Prefix
	// Mode selects the single forwarding header that is evaluated.
	Mode HeaderMode
	// OnReject is called for every refusal, for logging. Optional.
	OnReject func(r *http.Request, addr netip.Addr)
}

// Gate refuses requests from addresses that are not allowed, before the
// body is read. On success the verified address is placed in the context.
func Gate(cfg GateConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr, err := ClientIP(r, cfg.Mode, cfg.Trusted)
			if err != nil || !cfg.Allow.Contains(addr) {
				if cfg.OnReject != nil {
					cfg.OnReject(r, addr)
				}
				// Terse on purpose — the reason goes to the log.
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, addr)))
		})
	}
}
