package application_test

import (
	"context"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
)

// Shared by default-tag tests and the tagged client expansion scenarios.
func expansionCredential(t *testing.T, store *sqlite.Store, result application.CreationResult, index int) access.Payload {
	t.Helper()
	bindings, err := store.Bindings(context.Background(), result.InboundID)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the creation response's Alice/Bob order rather than repository sorting.
	for _, b := range bindings {
		if b.ID == result.Bindings[index].BindingID {
			c, err := store.RevealCredential(context.Background(), b.CredentialID)
			if err != nil {
				t.Fatal(err)
			}
			return c.Payload
		}
	}
	t.Fatal("missing created binding")
	return nil
}
