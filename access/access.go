// Package access decides which verified caller may invoke which tool.
//
// The shipped decider is deliberately coarse. Request carries the full
// tool name and every verified claim, so a finer decider can replace it
// without changing this interface.
package access

import (
	"context"
	"errors"

	"github.com/strausmann/gangway/identity"
)

// ErrForbidden is returned for every refusal.
var ErrForbidden = errors.New("gangway: forbidden")

// ToolKind marks a tool as reading or writing.
type ToolKind string

// The two recognized tool kinds.
const (
	KindRead  ToolKind = "read"
	KindWrite ToolKind = "write"
)

// Request is one authorization question.
type Request struct {
	// Tool is the registered tool name.
	Tool string
	// Kind marks the tool as reading or writing.
	Kind ToolKind
	// Identity is the verified caller, nil when unauthenticated.
	Identity *identity.Identity
}

// Decider answers authorization questions. It returns nil to allow and
// ErrForbidden to refuse.
type Decider interface {
	Allow(ctx context.Context, req Request) error
}

type allowAll struct{}

// AllowAll permits every authenticated caller. Only for servers whose
// tools are all equally harmless.
func AllowAll() Decider { return allowAll{} }

func (allowAll) Allow(_ context.Context, req Request) error {
	if req.Identity == nil {
		return ErrForbidden
	}
	return nil
}
