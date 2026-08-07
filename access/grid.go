package access

import "context"

// GridConfig configures the shipped decider.
type GridConfig struct {
	// WritersClaim names the claim that carries roles, e.g. "roles" or
	// "groups". Empty means writing is refused unless
	// AllowWriteByDefault is set.
	WritersClaim string
	// WritersValue is the value that grants writing.
	WritersValue string
	// AllowWriteByDefault permits writing without any check. Use only
	// where every caller is trusted equally.
	AllowWriteByDefault bool
}

type grid struct{ cfg GridConfig }

// NewGrid returns the shipped decider: reading for every authenticated
// caller, writing only for holders of the configured role.
func NewGrid(cfg GridConfig) Decider { return &grid{cfg: cfg} }

func (g *grid) Allow(_ context.Context, req Request) error {
	if req.Identity == nil {
		return ErrForbidden
	}
	if req.Kind != KindWrite {
		return nil
	}
	if g.cfg.AllowWriteByDefault {
		return nil
	}
	if g.cfg.WritersClaim == "" || g.cfg.WritersValue == "" {
		return ErrForbidden // a forgotten setting must not open the server
	}
	if hasClaimValue(req.Identity.Claims, g.cfg.WritersClaim, g.cfg.WritersValue) {
		return nil
	}
	return ErrForbidden
}

// hasClaimValue accepts both shapes providers use: a list of strings and
// a single string.
func hasClaimValue(claims map[string]any, name, want string) bool {
	switch v := claims[name].(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}
