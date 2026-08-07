// Package backend supplies the credential a tool uses to reach the
// service behind the MCP server.
//
// Mapping a verified identity onto an account in that service is
// application-specific and stays with the server — PerUser takes a lookup
// function for exactly that reason.
package backend

import (
	"context"

	"github.com/strausmann/gangway/identity"
)

// TokenSource supplies the credential for one call.
//
// incoming is the bearer token the caller presented; it is empty unless
// the source needs it.
type TokenSource interface {
	TokenFor(ctx context.Context, id *identity.Identity, incoming string) (string, error)
}
