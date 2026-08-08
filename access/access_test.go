package access_test

import (
	"context"
	"errors"
	"testing"

	"github.com/strausmann/gangway/access"
)

func TestAllowAll(t *testing.T) {
	d := access.AllowAll()

	t.Run("an unauthenticated request is refused", func(t *testing.T) {
		err := d.Allow(context.Background(), access.Request{
			Tool: "delete_item", Kind: access.KindWrite, Identity: nil,
		})
		if !errors.Is(err, access.ErrForbidden) {
			t.Errorf("Allow returned %v, want ErrForbidden", err)
		}
	})

	t.Run("an authenticated reader is allowed", func(t *testing.T) {
		err := d.Allow(context.Background(), access.Request{
			Tool: "list_items", Kind: access.KindRead, Identity: id(nil),
		})
		if err != nil {
			t.Errorf("Allow returned %v, want nil", err)
		}
	})

	t.Run("an authenticated writer is allowed too — that is the point of AllowAll", func(t *testing.T) {
		err := d.Allow(context.Background(), access.Request{
			Tool: "delete_item", Kind: access.KindWrite, Identity: id(nil),
		})
		if err != nil {
			t.Errorf("Allow returned %v, want nil", err)
		}
	})
}
