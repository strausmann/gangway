package access_test

import (
	"context"
	"errors"
	"testing"

	"github.com/strausmann/gangway/access"
	"github.com/strausmann/gangway/identity"
)

func id(claims map[string]any) *identity.Identity {
	return &identity.Identity{Subject: "user-123", Claims: claims}
}

func TestGrid(t *testing.T) {
	d := access.NewGrid(access.GridConfig{
		WritersClaim: "roles",
		WritersValue: "mcp-writer",
	})

	tests := []struct {
		name      string
		req       access.Request
		wantAllow bool
	}{
		{
			name:      "reading is allowed without the role",
			req:       access.Request{Tool: "list_items", Kind: access.KindRead, Identity: id(nil)},
			wantAllow: true,
		},
		{
			name:      "writing is refused without the role",
			req:       access.Request{Tool: "delete_item", Kind: access.KindWrite, Identity: id(nil)},
			wantAllow: false,
		},
		{
			name: "writing is allowed with the role",
			req: access.Request{Tool: "delete_item", Kind: access.KindWrite,
				Identity: id(map[string]any{"roles": []any{"other", "mcp-writer"}})},
			wantAllow: true,
		},
		{
			name: "writing is allowed with the role as a plain string",
			req: access.Request{Tool: "delete_item", Kind: access.KindWrite,
				Identity: id(map[string]any{"roles": "mcp-writer"})},
			wantAllow: true,
		},
		{
			name: "a different role does not grant writing",
			req: access.Request{Tool: "delete_item", Kind: access.KindWrite,
				Identity: id(map[string]any{"roles": []any{"reader"}})},
			wantAllow: false,
		},
		{
			name:      "an unauthenticated request is refused",
			req:       access.Request{Tool: "list_items", Kind: access.KindRead, Identity: nil},
			wantAllow: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := d.Allow(context.Background(), tc.req)
			if tc.wantAllow && err != nil {
				t.Errorf("Allow returned %v, want nil", err)
			}
			if !tc.wantAllow && !errors.Is(err, access.ErrForbidden) {
				t.Errorf("Allow returned %v, want ErrForbidden", err)
			}
		})
	}
}

func TestGridWithoutClaimRefusesAllWrites(t *testing.T) {
	// No claim configured and no explicit opt-in: writing is off. This is
	// the safe default — a forgotten setting must not open the server.
	d := access.NewGrid(access.GridConfig{})

	err := d.Allow(context.Background(), access.Request{
		Tool: "delete_item", Kind: access.KindWrite, Identity: id(nil),
	})
	if !errors.Is(err, access.ErrForbidden) {
		t.Errorf("Allow returned %v, want ErrForbidden", err)
	}
}

func TestGridAllowWriteByDefault(t *testing.T) {
	d := access.NewGrid(access.GridConfig{AllowWriteByDefault: true})

	if err := d.Allow(context.Background(), access.Request{
		Tool: "delete_item", Kind: access.KindWrite, Identity: id(nil),
	}); err != nil {
		t.Errorf("Allow returned %v, want nil", err)
	}
}

func TestGridAcceptsStringSliceClaim(t *testing.T) {
	// Claims usually arrive as []any (JSON decoding), but the claim map
	// is caller-provided — a []string built directly in Go must work
	// too, not just the JSON-decoded shape.
	d := access.NewGrid(access.GridConfig{
		WritersClaim: "roles",
		WritersValue: "mcp-writer",
	})

	t.Run("grants writing when the role is present", func(t *testing.T) {
		err := d.Allow(context.Background(), access.Request{
			Tool: "delete_item", Kind: access.KindWrite,
			Identity: id(map[string]any{"roles": []string{"other", "mcp-writer"}}),
		})
		if err != nil {
			t.Errorf("Allow returned %v, want nil", err)
		}
	})

	t.Run("refuses writing when the role is absent", func(t *testing.T) {
		err := d.Allow(context.Background(), access.Request{
			Tool: "delete_item", Kind: access.KindWrite,
			Identity: id(map[string]any{"roles": []string{"reader"}}),
		})
		if !errors.Is(err, access.ErrForbidden) {
			t.Errorf("Allow returned %v, want ErrForbidden", err)
		}
	})
}

func TestGridUnrecognizedClaimShapeRefusesWriting(t *testing.T) {
	// A claim value that is neither string, []any nor []string (e.g. a
	// number) must not be mistaken for a match.
	d := access.NewGrid(access.GridConfig{
		WritersClaim: "roles",
		WritersValue: "mcp-writer",
	})

	err := d.Allow(context.Background(), access.Request{
		Tool: "delete_item", Kind: access.KindWrite,
		Identity: id(map[string]any{"roles": 42}),
	})
	if !errors.Is(err, access.ErrForbidden) {
		t.Errorf("Allow returned %v, want ErrForbidden", err)
	}
}
